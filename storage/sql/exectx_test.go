//go:build cgo
// +build cgo

package sql

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
)

// TestExecTxRollsBackOnPanic covers a callback that panics inside ExecTx.
//
// ExecTx used to roll back only when the callback returned an error, so a panic
// unwound past it leaving the transaction open. A caller that recovers - an
// HTTP handler, for instance - then leaves the connection checked out for the
// life of the process. That is unrecoverable on sqlite, where the pool is
// limited to a single connection (SetMaxOpenConns(1)) and database/sql applies
// no timeout when acquiring one: every later storage operation blocks
// indefinitely behind the leaked transaction.
//
// A deferred rollback closes that path. After a successful Commit it is a no-op
// returning sql.ErrTxDone, so it costs nothing on the happy path.
//
// The test is written to fail by timeout rather than hang, so a regression
// reports instead of wedging the test run.
func TestExecTxRollsBackOnPanic(t *testing.T) {
	s := newSQLiteStorage(t)
	ctx := context.Background()

	const tokenID = "panic-token"

	// The callback only runs once the row has been found, so the token has to
	// exist for the panic to happen inside the transaction.
	if err := s.CreateRefresh(ctx, storage.RefreshToken{
		ID:          tokenID,
		Token:       "token",
		ClientID:    "client",
		ConnectorID: "conn",
		Claims:      storage.Claims{UserID: "user"},
		CreatedAt:   time.Now().UTC(),
		LastUsed:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected the panic to propagate")
			}
		}()
		_ = s.UpdateRefreshToken(ctx, tokenID,
			func(old storage.RefreshToken) (storage.RefreshToken, error) {
				panic("boom")
			})
	}()

	// If the transaction leaked, this blocks rather than returning.
	done := make(chan error, 1)
	go func() {
		_, err := s.GetOfflineSessions(ctx, "any", "any")
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != storage.ErrNotFound {
			t.Fatalf("unexpected error after panic: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("leaked transaction: storage is unusable after a panicking " +
			"ExecTx callback; ExecTx needs a deferred Rollback")
	}
}

func newSQLiteStorage(t *testing.T) storage.Storage {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	// File-backed rather than :memory:, so the single-connection behavior
	// matches a real deployment.
	o := &SQLite3{File: t.TempDir() + "/dex.db"}
	conn, err := o.open(logger)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}
