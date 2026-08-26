//go:build cgo
// +build cgo

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage/sql"
)

// TestRefreshTokenSQLiteNoNestedStorageRead guards the refresh grant against
// reading from storage while a storage transaction is open.
//
// Rotate invokes the freshIdentity callback from inside
// storage.UpdateRefreshToken. The SQL backend limits sqlite to a single
// connection (SetMaxOpenConns(1)), held for the lifetime of the transaction, so
// a storage read issued from that callback waits for the connection its own
// caller holds. database/sql applies no timeout when acquiring a connection, so
// this does not surface as a slow request: the transaction is never released
// and every subsequent storage operation in the process blocks behind it.
//
// The refresh grant reached that state through connector-data resolution.
// Rotate clears ConnectorData on every path, and connector data is only read
// from the offline session when the token does not carry it, so the fault needs
// two refreshes to appear:
//
//	refresh 1  token carries ConnectorData  -> returns early, and clears it
//	refresh 2  ConnectorData now empty      -> reads the offline session
//
// A single refresh therefore passes even against the unfixed code; the test
// performs two.
//
// Memory storage cannot reproduce this - it has no connection pool - so this
// test is deliberately sqlite-backed, and is the only place the constraint is
// exercised end to end.
func TestRefreshTokenSQLiteNoNestedStorageRead(t *testing.T) {
	logger := newLogger(t)

	sqlStorage, err := (&sql.SQLite3{File: t.TempDir() + "/dex.db"}).Open(logger)
	require.NoError(t, err, "open sqlite storage")
	t.Cleanup(func() { sqlStorage.Close() })

	httpServer, s := newTestServer(t, func(c *Config) {
		c.Storage = sqlStorage
	})
	defer httpServer.Close()

	mockRefreshTokenTestStorage(t, s.storage, false)

	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "/token")

	// refresh performs one refresh_token grant and returns the rotated token.
	// The request is served on its own goroutine so that a regression fails the
	// test by timeout instead of hanging the run indefinitely.
	refresh := func(t *testing.T, token string) string {
		t.Helper()

		v := url.Values{}
		v.Add("grant_type", "refresh_token")
		v.Add("refresh_token", token)

		req, err := http.NewRequest("POST", u.String(), bytes.NewBufferString(v.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
		req.SetBasicAuth("test", "barfoo")

		rr := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.ServeHTTP(rr, req)
		}()

		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("refresh_token grant did not complete within 20s: the " +
				"rotation callback is reading from storage while holding the " +
				"only sqlite connection, and is waiting for that connection " +
				"to be released by itself")
		}

		require.Equal(t, http.StatusOK, rr.Code, "refresh failed: %s", rr.Body.String())

		var res struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &res))
		require.NotEmpty(t, res.RefreshToken)
		return res.RefreshToken
	}

	first, err := internal.Marshal(&internal.RefreshToken{RefreshId: "test", Token: "bar"})
	require.NoError(t, err)

	// Clears ConnectorData; passes with or without the fix.
	second := refresh(t, first)

	// Reads the offline session for connector data. Deadlocks without the fix.
	refresh(t, second)
}
