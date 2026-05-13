package tcpguard

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	Client redis.UniversalClient
	Prefix string
}

func (s RedisStore) SaveApproval(ctx context.Context, approval ApprovalRecord) error {
	data, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	pipe := s.Client.TxPipeline()
	pipe.Set(ctx, s.key("approval:"+approval.ID), data, 0)
	pipe.SAdd(ctx, s.key("approval:index"), approval.ID)
	pipe.SAdd(ctx, s.key("approval:status:"+string(approval.Status)), approval.ID)
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
	ids, err := s.Client.SMembers(ctx, s.key(index)).Result()
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
	pipe.Set(ctx, s.key("approval:"+approval.ID), data, 0)
	pipe.SAdd(ctx, s.key("approval:index"), approval.ID)
	pipe.SAdd(ctx, s.key("approval:status:"+string(approval.Status)), approval.ID)
	if found && existing.Status != "" && existing.Status != approval.Status {
		pipe.SRem(ctx, s.key("approval:status:"+string(existing.Status)), approval.ID)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func NewRedisStore(client redis.UniversalClient, prefix string) RedisStore {
	return RedisStore{Client: client, Prefix: prefix}
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
