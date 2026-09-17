package routes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dativa-lv/eudi-verifier-core/internal/sessions"
	"github.com/dativa-lv/eudi-verifier-core/internal/testwallet"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
)

const canaryValue = "CANARY-CLAIM-VALUE-3407"

// valkeyValues returns every stored value for key regardless of its Redis type
// (string / list / set / zset / hash), so the canary grep covers the WHOLE
// keyspace, not just string keys — a leak into any structure fails the test.
func valkeyValues(t *testing.T, mr *miniredis.Miniredis, key string) []string {
	t.Helper()
	switch mr.Type(key) {
	case "string":
		v, err := mr.Get(key)
		qt.Assert(t, qt.IsNil(err))
		return []string{v}
	case "list":
		v, err := mr.List(key)
		qt.Assert(t, qt.IsNil(err))
		return v
	case "set":
		v, err := mr.Members(key)
		qt.Assert(t, qt.IsNil(err))
		return v
	case "zset":
		v, err := mr.ZMembers(key)
		qt.Assert(t, qt.IsNil(err))
		return v
	case "hash":
		fields, err := mr.HKeys(key)
		qt.Assert(t, qt.IsNil(err))
		out := make([]string, 0, 2*len(fields))
		for _, f := range fields {
			out = append(out, f, mr.HGet(key, f))
		}
		return out
	default:
		return nil
	}
}

// extractJWE pulls result_jwe out of a handoff envelope's JSON.
func extractJWE(t *testing.T, raw string) []byte {
	t.Helper()
	var env struct {
		ResultJWE string `json:"result_jwe"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(raw), &env)))
	return []byte(env.ResultJWE)
}

// TestVerifiedDeletionCanary is the acceptance proof:
// a canary claim value is driven through the full ten-step pipeline
// via the real wallet endpoints, then EVERY store this service touches is
// grepped for it. After handoff: (a) no Valkey key/value contains the canary in
// cleartext, (b) the DB snapshot (session rows + reports) carries claim NAMES
// but no values, (c) the session-scoped Valkey keys are DELETED, and (d) the
// encrypted handoff payload — opaque ciphertext, NOT a plaintext leak — still
// decrypts to the canary for the legitimate consumer.
func TestVerifiedDeletionCanary(t *testing.T) {
	f := newFixture(t)
	created, err := f.app.SessionCreator().Create(t.Context(), sessions.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-del",
		Flow: oid4vp.CrossDevice, Query: *dcql.PresetPIDFull(),
		WebhookURL: "https://client.test/hook",
	})
	qt.Assert(t, qt.IsNil(err))

	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	// PresetPIDFull's credential ids are pid_mdoc and pid_sdjwt (verified
	// against go-dcql presets) — drive the canary through BOTH presented
	// credentials so it exercises the mdoc and SD-JWT assembly paths.
	status, _, err := f.wallet.Respond(t.Context(), ro,
		testwallet.WithClaims("pid_mdoc", map[string]any{"family_name": canaryValue}),
		testwallet.WithClaims("pid_sdjwt", map[string]any{"family_name": canaryValue}))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(status, 200))

	// (a) Grep EVERY Valkey key/value for the canary — including the handoff
	// payload, whose result_jwe is ciphertext, so this passes there too.
	mr := f.app.TestMiniredis()
	for _, key := range mr.Keys() {
		for _, v := range valkeyValues(t, mr, key) {
			qt.Assert(t, qt.IsFalse(strings.Contains(v, canaryValue)),
				qt.Commentf("valkey key %s leaked the claim value", key))
		}
	}

	// (b) DB snapshot: everything the (fake) session-metadata store holds.
	dump := f.app.SessionDBFakeDump()
	qt.Assert(t, qt.IsFalse(strings.Contains(string(dump), canaryValue)))
	qt.Assert(t, qt.IsTrue(strings.Contains(string(dump), "family_name"))) // names persisted

	// (c) Session-scoped keys deleted (cross-device success mints no
	// response_code, so Finalize deletes the session — finalize.go).
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:session:"+created.SessionID)))
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:session:"+created.SessionID+":served")))
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:session:"+created.SessionID+":consumed")))

	// (d) The handoff payload exists (ciphertext) and decrypts to the canary.
	raw, err := mr.Get("vc:handoff:payload:" + created.SessionID)
	qt.Assert(t, qt.IsNil(err))
	plain := f.app.DecryptHandoffForTest(extractJWE(t, raw))
	qt.Assert(t, qt.IsTrue(strings.Contains(string(plain), canaryValue)))
}

// TestDeletionOnFailure proves deletion happens on FAILURE too (ARF AS-RP-51-013):
// a revoked credential short-circuits the pipeline at step 5, the session keys
// are still deleted, and a report-only handoff (no credentials member, no
// attribute values) is enqueued.
func TestDeletionOnFailure(t *testing.T) {
	f := newFixture(t)
	created := f.createSession(t, oid4vp.CrossDevice)
	ro, err := f.wallet.FetchRequestObject(t.Context(), created.RequestURI)
	qt.Assert(t, qt.IsNil(err))
	_, _, err = f.wallet.Respond(t.Context(), ro,
		testwallet.WithRevokedCredential(),
		testwallet.WithClaims("pid_sdjwt", map[string]any{"family_name": canaryValue}))
	qt.Assert(t, qt.IsNil(err))

	mr := f.app.TestMiniredis()
	qt.Assert(t, qt.IsFalse(mr.Exists("vc:session:"+created.SessionID)))
	raw, err := mr.Get("vc:handoff:payload:" + created.SessionID)
	qt.Assert(t, qt.IsNil(err))
	plain := f.app.DecryptHandoffForTest(extractJWE(t, raw))
	qt.Assert(t, qt.IsFalse(strings.Contains(string(plain), canaryValue))) // report only
	qt.Assert(t, qt.IsTrue(strings.Contains(string(plain), `"outcome":"failed"`)))
}
