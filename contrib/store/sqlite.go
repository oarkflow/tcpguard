package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/tcpguard"
	_ "modernc.org/sqlite"
)

func init() {
	tcpguard.RegisterDBDriverOpener("sqlite", func(dsn string) (*sql.DB, error) {
		return sql.Open("sqlite", dsn)
	})
}

type SQLiteStore struct {
	db        *sql.DB
	prefix    string
	retention tcpguard.RetentionPolicy
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &SQLiteStore{db: db, retention: tcpguard.DefaultRetentionPolicy()}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func NewSQLiteStoreWithDB(db *sql.DB) (*SQLiteStore, error) {
	s := &SQLiteStore{db: db, retention: tcpguard.DefaultRetentionPolicy()}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) WithPrefix(prefix string) *SQLiteStore {
	s.prefix = prefix
	return s
}

func (s *SQLiteStore) WithRetention(r tcpguard.RetentionPolicy) *SQLiteStore {
	s.retention = r
	return s
}

func (s *SQLiteStore) StorePrefix() string { return s.prefix }

func (s *SQLiteStore) init() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS tcpguard_kv (
		k TEXT PRIMARY KEY,
		v BLOB,
		expires_at INTEGER DEFAULT 0
	)`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS tcpguard_incidents (
		id TEXT PRIMARY KEY,
		data BLOB,
		created_at INTEGER
	)`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS tcpguard_audits (
		id TEXT PRIMARY KEY,
		seq INTEGER,
		chain_hash TEXT,
		data BLOB,
		created_at INTEGER
	)`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS tcpguard_approvals (
		id TEXT PRIMARY KEY,
		status TEXT,
		data BLOB,
		updated_at INTEGER
	)`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_tcpguard_audits_seq ON tcpguard_audits(seq)`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_tcpguard_approvals_status ON tcpguard_approvals(status)`)
	return err
}

func (s *SQLiteStore) key(k string) string { return s.prefix + k }

func (s *SQLiteStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT v, expires_at FROM tcpguard_kv WHERE k = ?`, s.key(key))
	var v []byte
	var expiresAt int64
	if err := row.Scan(&v, &expiresAt); err == sql.ErrNoRows {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	if expiresAt > 0 && time.Now().UnixMilli() > expiresAt {
		_ = s.Delete(ctx, key)
		return nil, false, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, true, nil
}

func (s *SQLiteStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var expiresAt int64
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl).UnixMilli()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO tcpguard_kv (k, v, expires_at) VALUES (?, ?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v, expires_at = excluded.expires_at`, s.key(key), value, expiresAt)
	return err
}

func (s *SQLiteStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM tcpguard_kv WHERE k = ?`, s.key(key))
	return err
}

func (s *SQLiteStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, `SELECT v FROM tcpguard_kv WHERE k = ?`, s.key(key))
	var raw []byte
	if err := row.Scan(&raw); err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	var n int64
	for _, ch := range raw {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int64(ch-'0')
		}
	}
	n++
	var expiresAt int64
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl).UnixMilli()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tcpguard_kv (k, v, expires_at) VALUES (?, ?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v, expires_at = excluded.expires_at`, s.key(key), []byte(fmt.Sprintf("%d", n)), expiresAt); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLiteStore) resolvedRetention() tcpguard.RetentionPolicy {
	base := tcpguard.DefaultRetentionPolicy()
	r := s.retention
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

func (s *SQLiteStore) SaveIncident(ctx context.Context, incident tcpguard.Incident) error {
	data, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO tcpguard_incidents (id, data, created_at) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET data = excluded.data, created_at = excluded.created_at`, incident.ID, data, time.Now().Unix())
	return err
}

func (s *SQLiteStore) ListIncidents(ctx context.Context) ([]tcpguard.Incident, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM tcpguard_incidents ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tcpguard.Incident
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var incident tcpguard.Incident
		if err := json.Unmarshal(data, &incident); err != nil {
			return nil, err
		}
		out = append(out, incident)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SaveAuditEnvelope(ctx context.Context, record tcpguard.AuditRecord) (tcpguard.AuditEnvelope, error) {
	payloadHash, err := tcpguard.AuditPayloadHash(record)
	if err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	var seq int64
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) + 1 FROM tcpguard_audits`)
	if err := row.Scan(&seq); err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	var previous string
	row = s.db.QueryRowContext(ctx, `SELECT chain_hash FROM tcpguard_audits ORDER BY seq DESC LIMIT 1`)
	if err := row.Scan(&previous); err != nil && err != sql.ErrNoRows {
		return tcpguard.AuditEnvelope{}, err
	}
	id := fmt.Sprintf("audit_%d", seq)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	chainHash := tcpguard.AuditChainHash(uint64(seq), timestamp, id, previous, payloadHash)
	envelope := tcpguard.AuditEnvelope{
		ID:           id,
		Sequence:     uint64(seq),
		Timestamp:    timestamp,
		PreviousHash: previous,
		PayloadHash:  payloadHash,
		ChainHash:    chainHash,
		Record:       record,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO tcpguard_audits (id, seq, chain_hash, data, created_at) VALUES (?, ?, ?, ?, ?)`, id, seq, chainHash, data, time.Now().Unix())
	if err != nil {
		return tcpguard.AuditEnvelope{}, err
	}
	return envelope, nil
}

func (s *SQLiteStore) ListAuditEnvelopes(ctx context.Context) ([]tcpguard.AuditEnvelope, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM tcpguard_audits ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tcpguard.AuditEnvelope
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var env tcpguard.AuditEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) GetAuditEnvelope(ctx context.Context, id string) (tcpguard.AuditEnvelope, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT data FROM tcpguard_audits WHERE id = ?`, id)
	var data []byte
	if err := row.Scan(&data); err == sql.ErrNoRows {
		return tcpguard.AuditEnvelope{}, false, nil
	} else if err != nil {
		return tcpguard.AuditEnvelope{}, false, err
	}
	var env tcpguard.AuditEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return tcpguard.AuditEnvelope{}, false, err
	}
	return env, true, nil
}

func (s *SQLiteStore) SaveApproval(ctx context.Context, approval tcpguard.ApprovalRecord) error {
	data, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO tcpguard_approvals (id, status, data, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET status = excluded.status, data = excluded.data, updated_at = excluded.updated_at`, approval.ID, string(approval.Status), data, time.Now().Unix())
	return err
}

func (s *SQLiteStore) GetApproval(ctx context.Context, id string) (tcpguard.ApprovalRecord, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT data FROM tcpguard_approvals WHERE id = ?`, id)
	var data []byte
	if err := row.Scan(&data); err == sql.ErrNoRows {
		return tcpguard.ApprovalRecord{}, false, nil
	} else if err != nil {
		return tcpguard.ApprovalRecord{}, false, err
	}
	var approval tcpguard.ApprovalRecord
	if err := json.Unmarshal(data, &approval); err != nil {
		return tcpguard.ApprovalRecord{}, false, err
	}
	return approval, true, nil
}

func (s *SQLiteStore) ListApprovals(ctx context.Context, status tcpguard.ApprovalStatus) ([]tcpguard.ApprovalRecord, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if status == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT data FROM tcpguard_approvals ORDER BY updated_at DESC`)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT data FROM tcpguard_approvals WHERE status = ? ORDER BY updated_at DESC`, string(status))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tcpguard.ApprovalRecord
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var approval tcpguard.ApprovalRecord
		if err := json.Unmarshal(data, &approval); err != nil {
			return nil, err
		}
		out = append(out, approval)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpdateApproval(ctx context.Context, approval tcpguard.ApprovalRecord) error {
	return s.SaveApproval(ctx, approval)
}

var (
	_ tcpguard.SecurityStore = (*SQLiteStore)(nil)
	_ tcpguard.PrefixedStore = (*SQLiteStore)(nil)
	_ tcpguard.IncidentStore = (*SQLiteStore)(nil)
	_ tcpguard.AuditStore    = (*SQLiteStore)(nil)
	_ tcpguard.ApprovalStore = (*SQLiteStore)(nil)
)
