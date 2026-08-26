package tokens

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func newTestStore(t *testing.T) (*RefreshStore, storage.Storage) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	store := memory.New(logger)
	return NewRefreshStore(store, time.Now, logger), store
}

func TestRefreshStoreCreate(t *testing.T) {
	ctx := context.Background()
	rt, store := newTestStore(t)
	auth := testAuthorization()

	first, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	var firstTok internal.RefreshToken
	require.NoError(t, internal.Unmarshal(first, &firstTok))

	stored, err := store.GetRefresh(ctx, firstTok.RefreshId)
	require.NoError(t, err)
	require.Equal(t, "client-1", stored.ClientID)
	require.Equal(t, auth.ConnectorData, stored.ConnectorData)

	sess, err := store.GetOfflineSessions(ctx, "u1", "mock")
	require.NoError(t, err)
	require.Contains(t, sess.Refresh, "client-1")

	// A second create for the same client replaces the old token.
	second, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	var secondTok internal.RefreshToken
	require.NoError(t, internal.Unmarshal(second, &secondTok))
	require.NotEqual(t, firstTok.RefreshId, secondTok.RefreshId)

	_, err = store.GetRefresh(ctx, firstTok.RefreshId)
	require.ErrorIs(t, err, storage.ErrNotFound)

	sess, err = store.GetOfflineSessions(ctx, "u1", "mock")
	require.NoError(t, err)
	require.Equal(t, secondTok.RefreshId, sess.Refresh["client-1"].ID)
}

func TestRefreshStoreRotate(t *testing.T) {
	ctx := context.Background()
	rt, store := newTestStore(t)

	require.NoError(t, store.CreateRefresh(ctx, storage.RefreshToken{
		ID: "r1", Token: "t1", ClientID: "client-1", ConnectorID: "mock",
		Claims: storage.Claims{UserID: "u1", Username: "alice"}, CreatedAt: time.Now(), LastUsed: time.Now(),
	}))
	require.NoError(t, store.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "u1", ConnID: "mock",
		Refresh: map[string]*storage.RefreshTokenRef{"client-1": {ID: "r1", ClientID: "client-1"}},
	}))
	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)

	strategy := NewRefreshStrategy(true, 0, 0, 0, nil) // rotation on, no reuse
	ident := connector.Identity{UserID: "u1", Username: "bob", Email: "bob@example.com"}
	freshIdentity := func(context.Context) (connector.Identity, error) { return ident, nil }

	raw, gotIdent, err := rt.Rotate(ctx, &stored, &internal.RefreshToken{RefreshId: "r1", Token: "t1"}, strategy, freshIdentity)
	require.NoError(t, err)
	require.Equal(t, ident, gotIdent)

	var newTok internal.RefreshToken
	require.NoError(t, internal.Unmarshal(raw, &newTok))
	require.Equal(t, "r1", newTok.RefreshId)
	require.NotEqual(t, "t1", newTok.Token, "token should have rotated")

	after, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	require.Equal(t, newTok.Token, after.Token)
	require.Equal(t, "t1", after.ObsoleteToken)
	require.Equal(t, "bob", after.Claims.Username, "claims refreshed from the identity")

	// Claiming with a token that is neither current nor obsolete is rejected.
	_, _, err = rt.Rotate(ctx, &after, &internal.RefreshToken{RefreshId: "r1", Token: "wrong"}, strategy, freshIdentity)
	require.Error(t, err)
}

func TestRefreshStoreRevoke(t *testing.T) {
	ctx := context.Background()
	rt, store := newTestStore(t)

	for _, tc := range []struct{ id, client string }{{"r1", "c1"}, {"r2", "c2"}} {
		require.NoError(t, store.CreateRefresh(ctx, storage.RefreshToken{
			ID: tc.id, ClientID: tc.client, ConnectorID: "mock", Claims: storage.Claims{UserID: "u1"},
		}))
	}
	require.NoError(t, store.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "u1", ConnID: "mock", ConnectorData: []byte("cd"),
		Refresh: map[string]*storage.RefreshTokenRef{
			"c1": {ID: "r1", ClientID: "c1"},
			"c2": {ID: "r2", ClientID: "c2"},
		},
	}))

	// RevokeClients is scoped to the named clients and leaves the rest of the user's
	// tokens alone.
	rt.RevokeClients(ctx, "u1", "mock", []string{"c1", "unknown"})

	_, err := store.GetRefresh(ctx, "r1")
	require.ErrorIs(t, err, storage.ErrNotFound)
	_, err = store.GetRefresh(ctx, "r2")
	require.NoError(t, err)

	sess, err := store.GetOfflineSessions(ctx, "u1", "mock")
	require.NoError(t, err)
	require.NotContains(t, sess.Refresh, "c1")
	require.Contains(t, sess.Refresh, "c2")

	// RevokeAll is the unscoped variant. The offline session survives with its refs
	// cleared and its connector data intact.
	rt.RevokeAll(ctx, "u1", "mock")

	_, err = store.GetRefresh(ctx, "r2")
	require.ErrorIs(t, err, storage.ErrNotFound)

	sess, err = store.GetOfflineSessions(ctx, "u1", "mock")
	require.NoError(t, err)
	require.Empty(t, sess.Refresh)
	require.Equal(t, []byte("cd"), sess.ConnectorData)
}

// The connector must not be contacted from inside the storage transaction: a
// connector that reads storage would ask the backend's pool for a second
// connection while the transaction holds the first.
//
// Asserted on the storage handed to the store, by failing any read that happens
// while the update callback is running.
func TestRotateCallsFreshIdentityOutsideTransaction(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	inner := memory.New(logger)

	tracking := &txTrackingStorage{Storage: inner}
	rt := NewRefreshStore(tracking, time.Now, logger)

	require.NoError(t, inner.CreateRefresh(ctx, storage.RefreshToken{
		ID: "r1", Token: "t1", ClientID: "client-1", ConnectorID: "mock",
		Claims: storage.Claims{UserID: "u1", Username: "alice"}, CreatedAt: time.Now(), LastUsed: time.Now(),
	}))
	require.NoError(t, inner.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "u1", ConnID: "mock",
		Refresh: map[string]*storage.RefreshTokenRef{"client-1": {ID: "r1", ClientID: "client-1"}},
	}))
	stored, err := inner.GetRefresh(ctx, "r1")
	require.NoError(t, err)

	// A connector that reads storage, as the built-in local connector does.
	freshIdentity := func(ctx context.Context) (connector.Identity, error) {
		if _, err := tracking.GetOfflineSessions(ctx, "u1", "mock"); err != nil {
			return connector.Identity{}, err
		}
		return connector.Identity{UserID: "u1", Username: "bob"}, nil
	}

	strategy := NewRefreshStrategy(true, 0, 0, 0, nil)
	_, _, err = rt.Rotate(ctx, &stored, &internal.RefreshToken{RefreshId: "r1", Token: "t1"}, strategy, freshIdentity)
	require.NoError(t, err, "a connector that reads storage must not be called inside the transaction")
}

// When the token may still be reused, no identity is needed and the connector is
// not contacted at all.
func TestRotateSkipsFreshIdentityWhenReusable(t *testing.T) {
	ctx := context.Background()
	rt, store := newTestStore(t)

	require.NoError(t, store.CreateRefresh(ctx, storage.RefreshToken{
		ID: "r1", Token: "t1", ClientID: "client-1", ConnectorID: "mock",
		Claims: storage.Claims{UserID: "u1", Username: "alice"}, CreatedAt: time.Now(), LastUsed: time.Now(),
	}))
	require.NoError(t, store.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "u1", ConnID: "mock",
		Refresh: map[string]*storage.RefreshTokenRef{"client-1": {ID: "r1", ClientID: "client-1"}},
	}))
	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)

	var calls int
	freshIdentity := func(context.Context) (connector.Identity, error) {
		calls++
		return connector.Identity{UserID: "u1", Username: "bob"}, nil
	}

	// Rotation on with a reuse window the token is well inside.
	strategy := NewRefreshStrategy(true, 0, 0, time.Hour, nil)
	_, _, err = rt.Rotate(ctx, &stored, &internal.RefreshToken{RefreshId: "r1", Token: "t1"}, strategy, freshIdentity)
	require.NoError(t, err)
	require.Zero(t, calls, "connector contacted for a token that may still be reused")
}

// The reuse window can lapse between the decision to skip the connector and the
// transaction re-checking it. The update then reports that it needs an identity
// and the rotation is retried once.
func TestRotateRetriesWhenReuseWindowLapses(t *testing.T) {
	ctx := context.Background()
	rt, store := newTestStore(t)

	lastUsed := time.Now()
	require.NoError(t, store.CreateRefresh(ctx, storage.RefreshToken{
		ID: "r1", Token: "t1", ClientID: "client-1", ConnectorID: "mock",
		Claims: storage.Claims{UserID: "u1", Username: "alice"}, CreatedAt: lastUsed, LastUsed: lastUsed,
	}))
	require.NoError(t, store.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "u1", ConnID: "mock",
		Refresh: map[string]*storage.RefreshTokenRef{"client-1": {ID: "r1", ClientID: "client-1"}},
	}))
	stored, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)

	// First reading of the clock is inside the window, every later one is past
	// it - so the pre-transaction check skips the connector and the callback
	// then finds it needs an identity after all.
	var reads int
	now := func() time.Time {
		reads++
		if reads == 1 {
			return lastUsed
		}
		return lastUsed.Add(time.Hour)
	}

	var calls int
	freshIdentity := func(context.Context) (connector.Identity, error) {
		calls++
		return connector.Identity{UserID: "u1", Username: "bob"}, nil
	}

	strategy := NewRefreshStrategy(true, 0, 0, time.Minute, now)
	_, ident, err := rt.Rotate(ctx, &stored, &internal.RefreshToken{RefreshId: "r1", Token: "t1"}, strategy, freshIdentity)
	require.NoError(t, err, "rotation should recover by retrying")
	require.Equal(t, 1, calls, "connector should be contacted exactly once, on the retry")
	require.Equal(t, "bob", ident.Username)

	after, err := store.GetRefresh(ctx, "r1")
	require.NoError(t, err)
	require.Equal(t, "bob", after.Claims.Username, "claims refreshed on the retry")
}

// txTrackingStorage fails any read issued while an update callback is running.
type txTrackingStorage struct {
	storage.Storage
	inUpdate bool
}

func (s *txTrackingStorage) UpdateRefreshToken(ctx context.Context, id string, updater func(storage.RefreshToken) (storage.RefreshToken, error)) error {
	return s.Storage.UpdateRefreshToken(ctx, id, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		s.inUpdate = true
		defer func() { s.inUpdate = false }()
		return updater(old)
	})
}

func (s *txTrackingStorage) GetOfflineSessions(ctx context.Context, userID, connID string) (storage.OfflineSessions, error) {
	if s.inUpdate {
		return storage.OfflineSessions{}, errors.New("storage read from inside the update transaction")
	}
	return s.Storage.GetOfflineSessions(ctx, userID, connID)
}
