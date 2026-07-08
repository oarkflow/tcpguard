package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/tcpguard"
	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	Client    redis.UniversalClient
	Prefix    string
	Retention tcpguard.RetentionPolicy
}

func (s RedisStore) resolvedRetention() tcpguard.RetentionPolicy {
	base := tcpguard.DefaultRetentionPolicy()
	r := s.Retention
	if r.IncidentsTTL > 0 {
		base.IncidentsTTL = r.IncidentsTTL
	}
	if r.AuditTTL > 0 {
		base.AuditTTL = r.AuditTTL
	}
	if r.ApprovalsTTL > 0 {
		base.ApprovalsTTL = r.ApprovalsTTL
	}
	if r.MaxIncidents > 0 {
		base.MaxIncidents = r.MaxIncidents
	}
	if r.MaxAudit > 0 {
		base.MaxAudit = r.MaxAudit
	}
	if r.MaxApprovals > 0 {
		base.MaxApprovals = r.MaxApprovals
	}
	return base
}

func (s RedisStore) SaveIncident(ctx context.Context, incident tcpguard.Incident) error {
	data, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	pipe := s.Client.TxPipeline()
	retention := s.resolvedRetention()
	ttl := retention.IncidentsTTL
	pipe.Set(ctx, s.key("incident:"+incident.ID), data, ttl)
	pipe.RPush(ctx, s.key("incident:index"), incident.ID)
	if retention.MaxIncidents > 0 {
		pipe.LTrim(ctx, s.key("incident:index"), -retention.MaxIncidents, -1)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (s RedisStore) ListIncidents(ctx context.Context) ([]tcpguard.Incident, error) {
	ids, err := s.Client.LRange(ctx, s.key("incident:index"), 0, -1).Result()
	if err != nil {
		return nil, err
	}
	out := make([]tcpguard.Incident, 0, len(ids))
	for _, id := range ids {
		data, found, err := s.Get(ctx, "incident:"+id)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		var incident tcpguard.Incident
		if err := json.Unmarshal(data, &incident); err != nil {
			return nil, err
		}
		out = append(out, incident)
	}
	return out, nil
}

func (s RedisStore) SaveAuditEnvelope(ctx context.Context, record tcpguard.AuditRecord) (tcpguard.AuditEnvelope, error) {
	payloadHash, err := tcpguard.AuditPayloadHash(record)
	if err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	sequence, err := s.Client.Incr(ctx, s.key("audit:seq")).Result()
	if err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	previous, err := s.Client.Get(ctx, s.key("audit:last_hash")).Result()
	if err == redis.Nil {
		previous = ""
	} else if err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	envelope := tcpguard.AuditEnvelope{
		ID:           "audit_" + fmt.Sprint(sequence),
		Sequence:     uint64(sequence),
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: previous,
		PayloadHash:  payloadHash,
		Record:       record,
	}
	envelope.ChainHash = tcpguard.AuditChainHash(envelope.Sequence, envelope.Timestamp, envelope.ID, envelope.PreviousHash, envelope.PayloadHash)
	data, err := json.Marshal(envelope)
	if err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	pipe := s.Client.TxPipeline()
	retention := s.resolvedRetention()
	ttl := retention.AuditTTL
	pipe.Set(ctx, s.key("audit:"+envelope.ID), data, ttl)
	pipe.RPush(ctx, s.key("audit:index"), envelope.ID)
	if retention.MaxAudit > 0 {
		pipe.LTrim(ctx, s.key("audit:index"), -retention.MaxAudit, -1)
	}
	pipe.Set(ctx, s.key("audit:last_hash"), envelope.ChainHash, 0)
	if _, err := pipe.Exec(ctx); err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	return envelope, nil
}

func (s RedisStore) ListAuditEnvelopes(ctx context.Context) ([]tcpguard.AuditEnvelope, error) {
	ids, err := s.Client.LRange(ctx, s.key("audit:index"), 0, -1).Result()
	if err != nil {
		return nil, err
	}
	out := make([]tcpguard.AuditEnvelope, 0, len(ids))
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

func (s RedisStore) GetAuditEnvelope(ctx context.Context, id string) (tcpguard.AuditEnvelope, bool, error) {
	data, found, err := s.Get(ctx, "audit:"+id)
	if err != nil || !found {
		return tcpguard.AuditEnvelope{}, found, err
	}
	var envelope tcpguard.AuditEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return tcpguard.AuditEnvelope{}, false, err
	}
	return envelope, true, nil
}

func (s RedisStore) SaveApproval(ctx context.Context, approval tcpguard.ApprovalRecord) error {
	data, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	pipe := s.Client.TxPipeline()
	retention := s.resolvedRetention()
	ttl := retention.ApprovalsTTL
	pipe.Set(ctx, s.key("approval:"+approval.ID), data, ttl)
	nowScore := float64(time.Now().Unix())
	pipe.ZAdd(ctx, s.key("approval:index"), redis.Z{Member: approval.ID, Score: nowScore})
	pipe.ZAdd(ctx, s.key("approval:status:"+string(approval.Status)), redis.Z{Member: approval.ID, Score: nowScore})
	if retention.MaxApprovals > 0 {
		evicted, err := s.Client.ZRange(ctx, s.key("approval:index"), 0, -(retention.MaxApprovals + 1)).Result()
		if err != nil && err != redis.Nil {
			return err
		}
		pipe.ZRemRangeByRank(ctx, s.key("approval:index"), 0, -(retention.MaxApprovals + 1))
		pipe.ZRemRangeByRank(ctx, s.key("approval:status:"+string(approval.Status)), 0, -(retention.MaxApprovals + 1))
		for _, id := range evicted {
			pipe.ZRem(ctx, s.key("approval:status:"+string(tcpguard.ApprovalPending)), id)
			pipe.ZRem(ctx, s.key("approval:status:"+string(tcpguard.ApprovalApproved)), id)
			pipe.ZRem(ctx, s.key("approval:status:"+string(tcpguard.ApprovalRejected)), id)
		}
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (s RedisStore) GetApproval(ctx context.Context, id string) (tcpguard.ApprovalRecord, bool, error) {
	data, found, err := s.Get(ctx, "approval:"+id)
	if err != nil || !found {
		return tcpguard.ApprovalRecord{}, found, err
	}
	var approval tcpguard.ApprovalRecord
	if err := json.Unmarshal(data, &approval); err != nil {
		return tcpguard.ApprovalRecord{}, false, err
	}
	return approval, true, nil
}

func (s RedisStore) ListApprovals(ctx context.Context, status tcpguard.ApprovalStatus) ([]tcpguard.ApprovalRecord, error) {
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
	out := make([]tcpguard.ApprovalRecord, 0, len(ids))
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

func (s RedisStore) UpdateApproval(ctx context.Context, approval tcpguard.ApprovalRecord) error {
	existing, found, err := s.GetApproval(ctx, approval.ID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	pipe := s.Client.TxPipeline()
	retention := s.resolvedRetention()
	ttl := retention.ApprovalsTTL
	pipe.Set(ctx, s.key("approval:"+approval.ID), data, ttl)
	nowScore := float64(time.Now().Unix())
	pipe.ZAdd(ctx, s.key("approval:index"), redis.Z{Member: approval.ID, Score: nowScore})
	pipe.ZAdd(ctx, s.key("approval:status:"+string(approval.Status)), redis.Z{Member: approval.ID, Score: nowScore})
	if found && existing.Status != "" && existing.Status != approval.Status {
		pipe.ZRem(ctx, s.key("approval:status:"+string(existing.Status)), approval.ID)
	}
	if retention.MaxApprovals > 0 {
		evicted, err := s.Client.ZRange(ctx, s.key("approval:index"), 0, -(retention.MaxApprovals + 1)).Result()
		if err != nil && err != redis.Nil {
			return err
		}
		pipe.ZRemRangeByRank(ctx, s.key("approval:index"), 0, -(retention.MaxApprovals + 1))
		pipe.ZRemRangeByRank(ctx, s.key("approval:status:"+string(approval.Status)), 0, -(retention.MaxApprovals + 1))
		for _, id := range evicted {
			pipe.ZRem(ctx, s.key("approval:status:"+string(tcpguard.ApprovalPending)), id)
			pipe.ZRem(ctx, s.key("approval:status:"+string(tcpguard.ApprovalApproved)), id)
			pipe.ZRem(ctx, s.key("approval:status:"+string(tcpguard.ApprovalRejected)), id)
		}
	}
	_, err = pipe.Exec(ctx)
	return err
}

func NewRedisStore(client redis.UniversalClient, prefix string) RedisStore {
	return RedisStore{Client: client, Prefix: prefix, Retention: tcpguard.DefaultRetentionPolicy()}
}

func (s RedisStore) StorePrefix() string { return s.Prefix }

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

var (
	_ tcpguard.SecurityStore = (*RedisStore)(nil)
	_ tcpguard.PrefixedStore = (*RedisStore)(nil)
	_ tcpguard.IncidentStore = (*RedisStore)(nil)
	_ tcpguard.AuditStore    = (*RedisStore)(nil)
	_ tcpguard.ApprovalStore = (*RedisStore)(nil)
)
