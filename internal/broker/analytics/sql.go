package analytics

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite", pure Go
)

// Driver names accepted by Open.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
	DriverNone     = "none"
)

var columns = []string{
	"ts", "request_id", "principal", "route", "model", "status", "stream",
	"latency_ms", "ttfb_ms", "queue_ms", "req_bytes", "resp_bytes",
	"prompt_tokens", "completion_tokens", "cached_tokens",
	"nonce_mode", "nonce_verified", "nonce_unknown", "nonce_tampered", "nonce_stripped", "nonce_canonical",
	"error_class",
}

const schema = `CREATE TABLE IF NOT EXISTS broker_requests (
	ts                TIMESTAMP NOT NULL,
	request_id        TEXT NOT NULL,
	principal         TEXT NOT NULL,
	route             TEXT NOT NULL,
	model             TEXT NOT NULL,
	status            INTEGER NOT NULL,
	stream            BOOLEAN NOT NULL,
	latency_ms        BIGINT NOT NULL,
	ttfb_ms           BIGINT NOT NULL,
	queue_ms          BIGINT NOT NULL,
	req_bytes         BIGINT NOT NULL,
	resp_bytes        BIGINT NOT NULL,
	prompt_tokens     BIGINT NOT NULL,
	completion_tokens BIGINT NOT NULL,
	cached_tokens     BIGINT NOT NULL,
	nonce_mode        TEXT NOT NULL,
	nonce_verified    INTEGER NOT NULL,
	nonce_unknown     INTEGER NOT NULL,
	nonce_tampered    INTEGER NOT NULL,
	nonce_stripped    INTEGER NOT NULL,
	nonce_canonical   INTEGER NOT NULL,
	error_class       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS broker_requests_ts ON broker_requests (ts);
CREATE INDEX IF NOT EXISTS broker_requests_principal_ts ON broker_requests (principal, ts);`

// SQLStore writes records through database/sql.
type SQLStore struct {
	db     *sql.DB
	insert string
}

// Open connects to driver/dsn and creates the table if it is missing.
// For sqlite, dsn is a file path or a "file:" URI; WAL and a busy timeout
// are set so readers (dashboards, sqlite3 shells) never stall the writer.
func Open(ctx context.Context, driver, dsn string) (*SQLStore, error) {
	var name string
	switch driver {
	case DriverSQLite:
		name = "sqlite"
		if !strings.HasPrefix(dsn, "file:") {
			dsn = "file:" + dsn
		}
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	case DriverPostgres:
		name = "pgx"
	default:
		return nil, fmt.Errorf("unknown analytics driver %q", driver)
	}
	db, err := sql.Open(name, dsn)
	if err != nil {
		return nil, err
	}
	if driver == DriverSQLite {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(4)
	}
	for _, stmt := range strings.Split(schema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("create analytics schema: %w", err)
		}
	}
	ph := make([]string, len(columns))
	for i := range ph {
		if driver == DriverPostgres {
			ph[i] = fmt.Sprintf("$%d", i+1)
		} else {
			ph[i] = "?"
		}
	}
	return &SQLStore{
		db:     db,
		insert: "INSERT INTO broker_requests (" + strings.Join(columns, ", ") + ") VALUES (" + strings.Join(ph, ", ") + ")",
	}, nil
}

// DB exposes the handle for summaries and tests.
func (s *SQLStore) DB() *sql.DB { return s.db }

// Insert writes batch in one transaction.
func (s *SQLStore) Insert(ctx context.Context, batch []Record) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, s.insert)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range batch {
		if _, err := stmt.ExecContext(ctx,
			r.Time.UTC(), r.RequestID, r.Principal, r.Route, r.Model, r.Status, r.Stream,
			r.LatencyMS, r.TTFBMS, r.QueueMS, r.ReqBytes, r.RespBytes,
			r.PromptTok, r.ComplTok, r.CachedTok,
			r.NonceMode, r.Verified, r.Unknown, r.Tampered, r.Stripped, r.Canonical,
			r.ErrorClass,
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Close closes the database.
func (s *SQLStore) Close() error { return s.db.Close() }
