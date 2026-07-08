package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/oarkflow/tcpguard"
)

func TestRedisResolvedRetentionDefaults(t *testing.T) {
	s := RedisStore{Retention: tcpguard.RetentionPolicy{AuditTTL: 5}}
	r := s.resolvedRetention()
	if r.IncidentsTTL <= 0 || r.AuditTTL != 5 || r.MaxApprovals <= 0 {
		t.Fatalf("redis resolved retention not merged correctly: %#v", r)
	}
}

func TestSQLiteResolvedRetentionDefaults(t *testing.T) {
	s := &SQLiteStore{retention: tcpguard.RetentionPolicy{AuditTTL: 5}}
	r := s.resolvedRetention()
	if r.IncidentsTTL <= 0 || r.AuditTTL != 5 || r.MaxApprovals <= 0 {
		t.Fatalf("sqlite resolved retention not merged correctly: %#v", r)
	}
}

func TestSQLiteStoreRoundTrip(t *testing.T) {
	s, err := NewSQLiteStore("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	if _, found, _ := s.Get(ctx, "missing"); found {
		t.Fatal("expected missing key to be absent")
	}
	if err := s.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("set: %v", err)
	}
	val, found, err := s.Get(ctx, "k")
	if err != nil || !found || string(val) != "v" {
		t.Fatalf("get after set: found=%v val=%q err=%v", found, string(val), err)
	}
	n, err := s.Incr(ctx, "counter", 0)
	if err != nil || n != 1 {
		t.Fatalf("incr first: n=%d err=%v", n, err)
	}
	n, err = s.Incr(ctx, "counter", 0)
	if err != nil || n != 2 {
		t.Fatalf("incr second: n=%d err=%v", n, err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, _ := s.Get(ctx, "k"); found {
		t.Fatal("expected deleted key to be absent")
	}
}

func TestSQLiteStoreIncidentAuditApproval(t *testing.T) {
	s, err := NewSQLiteStore("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	incident := tcpguard.Incident{ID: "inc-1", Severity: tcpguard.SeverityHigh, Status: "open", Summary: "test"}
	if err := s.SaveIncident(ctx, incident); err != nil {
		t.Fatalf("save incident: %v", err)
	}
	incidents, err := s.ListIncidents(ctx)
	if err != nil || len(incidents) != 1 || incidents[0].ID != "inc-1" {
		t.Fatalf("list incidents: %d err=%v", len(incidents), err)
	}
	env, err := s.SaveAuditEnvelope(ctx, tcpguard.AuditRecord{RequestID: "r1", Event: "test", Decision: "deny"})
	if err != nil {
		t.Fatalf("save audit: %v", err)
	}
	if env.ID == "" || env.ChainHash == "" {
		t.Fatalf("audit envelope incomplete: %+v", env)
	}
	envs, err := s.ListAuditEnvelopes(ctx)
	if err != nil || len(envs) != 1 {
		t.Fatalf("list audits: %d err=%v", len(envs), err)
	}
	approval := tcpguard.ApprovalRecord{ID: "ap-1", Status: tcpguard.ApprovalPending, RuleID: "rule-1", RequestedAt: time.Now()}
	if err := s.SaveApproval(ctx, approval); err != nil {
		t.Fatalf("save approval: %v", err)
	}
	got, found, err := s.GetApproval(ctx, "ap-1")
	if err != nil || !found || got.RuleID != "rule-1" {
		t.Fatalf("get approval: found=%v err=%v", found, err)
	}
	list, err := s.ListApprovals(ctx, tcpguard.ApprovalPending)
	if err != nil || len(list) != 1 {
		t.Fatalf("list approvals: %d err=%v", len(list), err)
	}
	approval.Status = tcpguard.ApprovalApproved
	if err := s.UpdateApproval(ctx, approval); err != nil {
		t.Fatalf("update approval: %v", err)
	}
	list, err = s.ListApprovals(ctx, tcpguard.ApprovalApproved)
	if err != nil || len(list) != 1 {
		t.Fatalf("list approved: %d err=%v", len(list), err)
	}
}

func TestSQLDataSourceLookup(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, status TEXT, locked BOOLEAN); INSERT INTO users (id, status, locked) VALUES ('user-1', 'suspended', true);`)
	if err != nil {
		t.Fatalf("seed sqlite: %v", err)
	}
	sqlSource := tcpguard.SQLDataSource{SourceID: "user-db", DB: db}
	sqlResult, err := sqlSource.Lookup(context.Background(), tcpguard.LookupRequest{
		Query:  "SELECT status, locked FROM users WHERE id = :user_id",
		Params: map[string]any{"user_id": "user-1"},
	})
	if err != nil || !sqlResult.Found || sqlResult.Fields["status"] != "suspended" || sqlResult.Fields["locked"] != true {
		t.Fatalf("sql result=%#v err=%v", sqlResult, err)
	}
}

func TestDBDriverOpenerRegistered(t *testing.T) {
	_, err := tcpguard.OpenDBDriver("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("expected sqlite opener to be registered: %v", err)
	}
}
