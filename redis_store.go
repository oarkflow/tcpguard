package tcpguard

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	Client    redis.UniversalClient
	Prefix    string
	Retention RetentionPolicy
}

func (s RedisStore) SaveIncident(ctx context.Context, incident Incident) error {
	data, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	pipe := s.Client.TxPipeline()
	ttl := s.Retention.IncidentsTTL
	if ttl <= 0 {
		ttl = DefaultRetentionPolicy().IncidentsTTL
	}
	pipe.Set(ctx, s.key("incident:"+incident.ID), data, ttl)
	pipe.RPush(ctx, s.key("incident:index"), incident.ID)
	if s.Retention.MaxIncidents > 0 {
		pipe.LTrim(ctx, s.key("incident:index"), -s.Retention.MaxIncidents, -1)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (s RedisStore) ListIncidents(ctx context.Context) ([]Incident, error) {
	ids, err := s.Client.LRange(ctx, s.key("incident:index"), 0, -1).Result()
	if err != nil {
		return nil, err
	}
	out := make([]Incident, 0, len(ids))
	for _, id := range ids {
		data, found, err := s.Get(ctx, "incident:"+id)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		var incident Incident
		if err := json.Unmarshal(data, &incident); err != nil {
			return nil, err
		}
		out = append(out, incident)
	}
	return out, nil
}

func (s RedisStore) SaveAuditEnvelope(ctx context.Context, record AuditRecord) (AuditEnvelope, error) {
	payloadHash, err := auditPayloadHash(record)
	if err != nil {
		return AuditEnvelope{}, err
	}
	sequence, err := s.Client.Incr(ctx, s.key("audit:seq")).Result()
	if err != nil {
		return AuditEnvelope{}, err
	}
	previous, err := s.Client.Get(ctx, s.key("audit:last_hash")).Result()
	if err == redis.Nil {
		previous = ""
	} else if err != nil {
		return AuditEnvelope{}, err
	}
	envelope := AuditEnvelope{
		ID:           "audit_" + fmt.Sprint(sequence),
		Sequence:     uint64(sequence),
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: previous,
		PayloadHash:  payloadHash,
		Record:       record,
	}
	envelope.ChainHash = auditChainHash(envelope.Sequence, envelope.Timestamp, envelope.ID, envelope.PreviousHash, envelope.PayloadHash)
	data, err := json.Marshal(envelope)
	if err != nil {
		return AuditEnvelope{}, err
	}
	pipe := s.Client.TxPipeline()
	ttl := s.Retention.AuditTTL
	if ttl <= 0 {
		ttl = DefaultRetentionPolicy().AuditTTL
	}
	pipe.Set(ctx, s.key("audit:"+envelope.ID), data, ttl)
	pipe.RPush(ctx, s.key("audit:index"), envelope.ID)
	if s.Retention.MaxAudit > 0 {
		pipe.LTrim(ctx, s.key("audit:index"), -s.Retention.MaxAudit, -1)
	}
	pipe.Set(ctx, s.key("audit:last_hash"), envelope.ChainHash, 0)
	if _, err := pipe.Exec(ctx); err != nil {
		return AuditEnvelope{}, err
	}
	return envelope, nil
}

func (s RedisStore) ListAuditEnvelopes(ctx context.Context) ([]AuditEnvelope, error) {
	ids, err := s.Client.LRange(ctx, s.key("audit:index"), 0, -1).Result()
	if err != nil {
		return nil, err
	}
	out := make([]AuditEnvelope, 0, len(ids))
	for _, id := range ids {
		envelope, found, err := s.GetAuditEnvelope(ctx, id)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, envelope)
		}
	}
	return out, nil
}

func (s RedisStore) GetAuditEnvelope(ctx context.Context, id string) (AuditEnvelope, bool, error) {
	data, found, err := s.Get(ctx, "audit:"+id)
	if err != nil || !found {
		return AuditEnvelope{}, found, err
	}
	var envelope AuditEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return AuditEnvelope{}, false, err
	}
	return envelope, true, nil
}

func (s RedisStore) SaveApproval(ctx context.Context, approval ApprovalRecord) error {
	data, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	pipe := s.Client.TxPipeline()
	ttl := s.Retention.ApprovalsTTL
	if ttl <= 0 {
		ttl = DefaultRetentionPolicy().ApprovalsTTL
	}
	pipe.Set(ctx, s.key("approval:"+approval.ID), data, ttl)
	nowScore := float64(time.Now().Unix())
	pipe.ZAdd(ctx, s.key("approval:index"), redis.Z{Member: approval.ID, Score: nowScore})
	pipe.ZAdd(ctx, s.key("approval:status:"+string(approval.Status)), redis.Z{Member: approval.ID, Score: nowScore})
	if s.Retention.MaxApprovals > 0 {
		pipe.ZRemRangeByRank(ctx, s.key("approval:index"), 0, -(s.Retention.MaxApprovals + 1))
		pipe.ZRemRangeByRank(ctx, s.key("approval:status:"+string(approval.Status)), 0, -(s.Retention.MaxApprovals + 1))
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (s RedisStore) GetApproval(ctx context.Context, id string) (ApprovalRecord, bool, error) {
	data, found, err := s.Get(ctx, "approval:"+id)
	if err != nil || !found {
		return ApprovalRecord{}, found, err
	}
	var approval ApprovalRecord
	if err := json.Unmarshal(data, &approval); err != nil {
		return ApprovalRecord{}, false, err
	}
	return approval, true, nil
}

func (s RedisStore) ListApprovals(ctx context.Context, status ApprovalStatus) ([]ApprovalRecord, error) {
	index := "approval:index"
	if status != "" {
		index = "approval:status:" + string(status)
	}
	ids, err := s.Client.ZRevRange(ctx, s.key(index), 0, -1).Result()
	if err == nil && len(ids) == 0 {
		ids, err = s.Client.SMembers(ctx, s.key(index)).Result()
	}
	if err != nil {
		return nil, err
	}
	out := make([]ApprovalRecord, 0, len(ids))
	for _, id := range ids {
		record, found, err := s.GetApproval(ctx, id)
		if err != nil {
			return nil, err
		}
		if found && (status == "" || record.Status == status) {
			out = append(out, record)
		}
	}
	return out, nil
}

func (s RedisStore) UpdateApproval(ctx context.Context, approval ApprovalRecord) error {
	existing, found, err := s.GetApproval(ctx, approval.ID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	pipe := s.Client.TxPipeline()
	ttl := s.Retention.ApprovalsTTL
	if ttl <= 0 {
		ttl = DefaultRetentionPolicy().ApprovalsTTL
	}
	pipe.Set(ctx, s.key("approval:"+approval.ID), data, ttl)
	nowScore := float64(time.Now().Unix())
	pipe.ZAdd(ctx, s.key("approval:index"), redis.Z{Member: approval.ID, Score: nowScore})
	pipe.ZAdd(ctx, s.key("approval:status:"+string(approval.Status)), redis.Z{Member: approval.ID, Score: nowScore})
	if found && existing.Status != "" && existing.Status != approval.Status {
		pipe.ZRem(ctx, s.key("approval:status:"+string(existing.Status)), approval.ID)
	}
	if s.Retention.MaxApprovals > 0 {
		pipe.ZRemRangeByRank(ctx, s.key("approval:index"), 0, -(s.Retention.MaxApprovals + 1))
		pipe.ZRemRangeByRank(ctx, s.key("approval:status:"+string(approval.Status)), 0, -(s.Retention.MaxApprovals + 1))
	}
	_, err = pipe.Exec(ctx)
	return err
}

func NewRedisStore(client redis.UniversalClient, prefix string) RedisStore {
	return RedisStore{Client: client, Prefix: prefix, Retention: DefaultRetentionPolicy()}
}

func (s RedisStore) key(key string) string {
	return s.Prefix + key
}

func (s RedisStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	value, err := s.Client.Get(ctx, s.key(key)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (s RedisStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.Client.Set(ctx, s.key(key), value, ttl).Err()
}

func (s RedisStore) Delete(ctx context.Context, key string) error {
	return s.Client.Del(ctx, s.key(key)).Err()
}

func (s RedisStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	full := s.key(key)
	pipe := s.Client.TxPipeline()
	incr := pipe.Incr(ctx, full)
	if ttl > 0 {
		pipe.ExpireNX(ctx, full, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}
