//go:build cgo
// +build cgo

package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/server/connectors"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/sql"
)

// TestRefreshTokenSQLiteLocalConnector guards the refresh grant against
// contacting a connector from inside the storage transaction.
//
// The built-in local connector reads the password table when it refreshes an
// identity. Backends serve transactions from a connection pool, so a connector
// that reads storage while the transaction holds a connection asks for a second
// one; the SQL backend limits sqlite to a single connection, and database/sql
// applies no timeout when acquiring one, so it never resolves.
//
// A remote connector would not expose this - it reads no storage - so this test
// is deliberately built on the connector that does.
func TestRefreshTokenSQLiteLocalConnector(t *testing.T) {
	logger := newLogger(t)

	sqlStorage, err := (&sql.SQLite3{File: t.TempDir() + "/dex.db"}).Open(logger)
	require.NoError(t, err, "open sqlite storage")
	t.Cleanup(func() { sqlStorage.Close() })

	httpServer, s := newTestServerWith(t,
		[]storage.Connector{{ID: "local", Type: connectors.LocalConnector, Name: "local"}},
		func(c *Config) { c.Storage = sqlStorage })
	defer httpServer.Close()

	ctx := context.Background()
	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
		ID: "test", Secret: "barfoo", RedirectURIs: []string{"foo://bar.com/"},
	}))

	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, s.storage.CreatePassword(ctx, storage.Password{
		Email: "u@example.com", Hash: hash, Username: "u", UserID: "1",
	}))
	require.NoError(t, s.storage.CreateRefresh(ctx, storage.RefreshToken{
		ID: "tok", Token: "bar", ClientID: "test", ConnectorID: "local",
		Scopes:    []string{"openid", "offline_access"},
		Claims:    storage.Claims{UserID: "1", Username: "u", Email: "u@example.com"},
		CreatedAt: time.Now().UTC(), LastUsed: time.Now().UTC(),
	}))
	require.NoError(t, s.storage.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "1", ConnID: "local",
		Refresh: map[string]*storage.RefreshTokenRef{"test": {ID: "tok", ClientID: "test"}},
	}))

	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "/token")

	token, err := internal.Marshal(&internal.RefreshToken{RefreshId: "tok", Token: "bar"})
	require.NoError(t, err)

	v := url.Values{}
	v.Add("grant_type", "refresh_token")
	v.Add("refresh_token", token)

	req, err := http.NewRequest("POST", u.String(), bytes.NewBufferString(v.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test", "barfoo")

	// Served on its own goroutine so a regression fails by timeout rather than
	// hanging the test run.
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeHTTP(rr, req)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("refresh_token grant did not complete within 20s: the connector " +
			"is being called from inside the storage transaction, and its read " +
			"is waiting for the connection that transaction holds")
	}

	require.Equal(t, http.StatusOK, rr.Code, "refresh failed: %s", rr.Body.String())
}
