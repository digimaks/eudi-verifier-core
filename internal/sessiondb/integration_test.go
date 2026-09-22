//go:build integration

package sessiondb_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/digimaks/eudi-verifier-core/internal/sessiondb"

	"github.com/go-quicktest/qt"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Requires a Postgres with this service's schema applied (the migration image
// brings one up); the DSN comes from the environment.
// DSN uses the EXECUTE-only service role — the same one production uses.
func dsn() string {
	if v := os.Getenv("TEST_POSTGRES_DSN"); v != "" {
		return v
	}
	return "postgres://verifier_core_public:verifier_core_public_dev@127.0.0.1:55432/verifier"
}

func pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), dsn())
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(p.Close)
	return p
}

func TestProcedureRoundtrip(t *testing.T) {
	repo := sessiondb.NewPG(pool(t))
	ctx := context.Background()

	s, err := repo.Create(ctx, sessiondb.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-int-1",
		Flow: "cross_device", WebhookURL: "https://client.test/hook",
		Policy:    json.RawMessage(`{"revocation_fail_closed":true}`),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(s.ID), 26)) // ULID

	qt.Assert(t, qt.IsNil(repo.SetStatus(ctx, s.ID, "wallet_engaged")))
	qt.Assert(t, qt.IsNil(repo.SaveReport(ctx, s.ID, json.RawMessage(`{"outcome":"verified","checks":[]}`))))

	rep, err := repo.GetReport(ctx, s.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(len(rep) > 0))
}

func TestUnknownSessionNotFound(t *testing.T) {
	repo := sessiondb.NewPG(pool(t))
	_, err := repo.Get(context.Background(), "01JZXNOSUCHSESSION00000000")
	qt.Assert(t, qt.IsNotNil(err)) // session:not_found → 404 problem
}

func TestInvalidStatusRejected(t *testing.T) {
	repo := sessiondb.NewPG(pool(t))
	ctx := context.Background()
	s, err := repo.Create(ctx, sessiondb.CreateInput{
		ClientID: "c", CorrelationID: "x", Flow: "same_device",
		WebhookURL: "https://client.test/hook", ExpiresAt: time.Now().Add(time.Minute),
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(repo.SetStatus(ctx, s.ID, "bogus"))) // session:invalid → 422
}

// Mandatory role-leak test: the service role has NO table access.
func TestRoleLeakDirectTableAccessFails(t *testing.T) {
	p := pool(t)
	_, err := p.Exec(context.Background(), "select * from session.session limit 1")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
	_, err = p.Exec(context.Background(), "insert into session.session (client_id, correlation_id, flow, webhook_url, expires_at) values ('x','x','same_device','https://x', now())")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
}
