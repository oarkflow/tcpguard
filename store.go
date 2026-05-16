package tcpguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

type memoryItem struct {
	value     []byte
	expiresAt time.Time
}

type MemoryStore struct {
	mu        sync.RWMutex
	items     map[string]memoryItem
	incidents []Incident
	approvals map[string]ApprovalRecord
	audits    map[string]AuditEnvelope
	auditIDs  []string
	lastAudit string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: map[string]memoryItem{}, approvals: map[string]ApprovalRecord{}, audits: map[string]AuditEnvelope{}}
}

func (s *MemoryStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	s.mu.RLock()
	item, ok := s.items[key]
	s.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		_ = s.Delete(ctx, key)
		return nil, false, nil
	}
	out := make([]byte, len(item.value))
	copy(out, item.value)
	return out, true, nil
}

func (s *MemoryStore) HasJoined(ctx context.Context, prefix, value string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	n := len(prefix) + len(value)
	if n <= 128 {
		var buf [128]byte
		copy(buf[:], prefix)
		copy(buf[len(prefix):], value)
		return s.hasUnsafeString(ctx, unsafe.String(&buf[0], n))
	}
	return s.hasUnsafeString(ctx, prefix+value)
}

func (s *MemoryStore) hasUnsafeString(ctx context.Context, key string) (bool, error) {
	s.mu.RLock()
	item, ok := s.items[key]
	s.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		_ = s.Delete(ctx, key)
		return false, nil
	}
	return true, nil
}

func (s *MemoryStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	item := memoryItem{value: append([]byte(nil), value...)}
	if ttl > 0 {
		item.expiresAt = time.Now().Add(ttl)
	}
	s.mu.Lock()
	s.items[key] = item
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.items, key)
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	item := s.items[key]
	if !item.expiresAt.IsZero() && now.After(item.expiresAt) {
		item.value = nil
	}
	var n int64
	for _, ch := range item.value {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int64(ch-'0')
		}
	}
	n++
	item.value = []byte(formatInt(n))
	if ttl > 0 && item.expiresAt.IsZero() {
		item.expiresAt = now.Add(ttl)
	}
	s.items[key] = item
	return n, nil
}

func (s *MemoryStore) SaveIncident(ctx context.Context, incident Incident) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.incidents = append(s.incidents, incident)
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) ListIncidents(ctx context.Context) ([]Incident, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Incident, len(s.incidents))
	copy(out, s.incidents)
	return out, nil
}

func (s *MemoryStore) SaveApproval(ctx context.Context, approval ApprovalRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.approvals == nil {
		s.approvals = map[string]ApprovalRecord{}
	}
	s.approvals[approval.ID] = approval
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) GetApproval(ctx context.Context, id string) (ApprovalRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return ApprovalRecord{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	approval, ok := s.approvals[id]
	return approval, ok, nil
}

func (s *MemoryStore) ListApprovals(ctx context.Context, status ApprovalStatus) ([]ApprovalRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ApprovalRecord, 0, len(s.approvals))
	for _, approval := range s.approvals {
		if status == "" || approval.Status == status {
			out = append(out, approval)
		}
	}
	return out, nil
}

func (s *MemoryStore) UpdateApproval(ctx context.Context, approval ApprovalRecord) error {
	return s.SaveApproval(ctx, approval)
}

func (s *MemoryStore) SaveAuditEnvelope(ctx context.Context, record AuditRecord) (AuditEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return AuditEnvelope{}, err
	}
	payloadHash, err := auditPayloadHash(record)
	if err != nil {
		return AuditEnvelope{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.audits == nil {
		s.audits = map[string]AuditEnvelope{}
	}
	sequence := uint64(len(s.auditIDs) + 1)
	id := "audit_" + formatInt(int64(sequence))
	envelope := AuditEnvelope{
		ID:           id,
		Sequence:     sequence,
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: s.lastAudit,
		PayloadHash:  payloadHash,
		Record:       record,
	}
	envelope.ChainHash = auditChainHash(envelope.Sequence, envelope.Timestamp, envelope.ID, envelope.PreviousHash, envelope.PayloadHash)
	s.audits[id] = envelope
	s.auditIDs = append(s.auditIDs, id)
	s.lastAudit = envelope.ChainHash
	return envelope, nil
}

func (s *MemoryStore) ListAuditEnvelopes(ctx context.Context) ([]AuditEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEnvelope, 0, len(s.auditIDs))
	for _, id := range s.auditIDs {
		out = append(out, s.audits[id])
	}
	return out, nil
}

func (s *MemoryStore) GetAuditEnvelope(ctx context.Context, id string) (AuditEnvelope, bool, error) {
	if err := ctx.Err(); err != nil {
		return AuditEnvelope{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	envelope, ok := s.audits[id]
	return envelope, ok, nil
}

func VerifyAuditChain(envelopes []AuditEnvelope) error {
	var previous string
	var sequence uint64
	for i, envelope := range envelopes {
		if envelope.Sequence == 0 {
			return fmt.Errorf("audit envelope %d has zero sequence", i)
		}
		if sequence != 0 && envelope.Sequence != sequence+1 {
			return fmt.Errorf("audit envelope %s has non-contiguous sequence", envelope.ID)
		}
		if envelope.PreviousHash != previous {
			return fmt.Errorf("audit envelope %s previous hash mismatch", envelope.ID)
		}
		payloadHash, err := auditPayloadHash(envelope.Record)
		if err != nil {
			return err
		}
		if payloadHash != envelope.PayloadHash {
			return fmt.Errorf("audit envelope %s payload hash mismatch", envelope.ID)
		}
		if auditChainHash(envelope.Sequence, envelope.Timestamp, envelope.ID, envelope.PreviousHash, envelope.PayloadHash) != envelope.ChainHash {
			return fmt.Errorf("audit envelope %s chain hash mismatch", envelope.ID)
		}
		previous = envelope.ChainHash
		sequence = envelope.Sequence
	}
	return nil
}

func auditPayloadHash(record AuditRecord) (string, error) {
	var buf [2048]byte
	data := appendAuditRecordHash(buf[:0], record)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func appendAuditRecordHash(dst []byte, record AuditRecord) []byte {
	dst = appendHashString(dst, record.RequestID)
	dst = appendHashString(dst, record.Event)
	dst = appendHashString(dst, record.Decision)
	dst = strconvAppendFloat(dst, record.RiskScore)
	dst = appendHashString(dst, string(record.Severity))
	dst = appendHashStringSlice(dst, record.MatchedRules)
	dst = appendHashStringSlice(dst, record.Findings)
	dst = appendHashStringSlice(dst, record.Evidence)
	dst = strconvAppendInt(dst, int64(len(record.ActionResults)))
	for _, action := range record.ActionResults {
		dst = appendHashString(dst, action.ID)
		dst = appendHashString(dst, action.Type)
		dst = appendHashString(dst, action.Status)
		dst = appendHashString(dst, action.Error)
		dst = appendHashTime(dst, action.At)
	}
	dst = appendHashStringSlice(dst, record.ApprovalIDs)
	dst = appendHashString(dst, record.Explanation)
	dst = appendHashString(dst, record.RequestFingerprint)
	dst = appendHashString(dst, record.PolicyVersion)
	dst = appendHashString(dst, record.ConfigHash)
	dst = appendHashTime(dst, record.At)
	return dst
}

func appendHashStringSlice(dst []byte, values []string) []byte {
	dst = strconvAppendInt(dst, int64(len(values)))
	dst = append(dst, 0)
	for _, value := range values {
		dst = appendHashString(dst, value)
	}
	return dst
}

func appendHashString(dst []byte, value string) []byte {
	dst = strconvAppendInt(dst, int64(len(value)))
	dst = append(dst, ':')
	dst = append(dst, value...)
	dst = append(dst, 0)
	return dst
}

func appendHashTime(dst []byte, value time.Time) []byte {
	if value.IsZero() {
		return appendHashString(dst, "")
	}
	return value.AppendFormat(dst, time.RFC3339Nano)
}

func strconvAppendInt(dst []byte, n int64) []byte {
	if n < 0 {
		dst = append(dst, '-')
		return strconvAppendUint(dst, uint64(-n))
	}
	return strconvAppendUint(dst, uint64(n))
}

func strconvAppendFloat(dst []byte, n float64) []byte {
	return strconv.AppendFloat(dst, n, 'g', -1, 64)
}

func auditChainHash(sequence uint64, timestamp, id, previousHash, payloadHash string) string {
	var buf [512]byte
	data := strconvAppendUint(buf[:0], sequence)
	data = append(data, '\n')
	data = append(data, timestamp...)
	data = append(data, '\n')
	data = append(data, id...)
	data = append(data, '\n')
	data = append(data, previousHash...)
	data = append(data, '\n')
	data = append(data, payloadHash...)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func strconvAppendUint(dst []byte, n uint64) []byte {
	if n == 0 {
		return append(dst, '0')
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return append(dst, buf[i:]...)
}

func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
