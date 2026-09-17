package sessions_test

import (
	"encoding/json"
	"testing"

	verifiercore "github.com/dativa-lv/eudi-verifier-core"
	"github.com/dativa-lv/eudi-verifier-core/internal/policy"
	"github.com/dativa-lv/eudi-verifier-core/internal/sessions"

	dcql "github.com/gmb-eudi/go-dcql"
	oid4vp "github.com/gmb-eudi/go-oid4vp"

	"github.com/go-quicktest/qt"
)

// The browser request member the wallet receives ([OID4VP §A]). Only the
// parts that distinguish the two modes are decoded: the protocol identifier,
// and — for the signed variant — the claims that carry our identity.
type dcapiMember struct {
	Protocol string `json:"protocol"`
	Data     struct {
		Request         string   `json:"request"`
		ClientID        string   `json:"client_id"`
		ExpectedOrigins []string `json:"expected_origins"`
		Nonce           string   `json:"nonce"`
	} `json:"data"`
}

func decodeMember(t *testing.T, member []byte) dcapiMember {
	t.Helper()
	var m dcapiMember
	qt.Assert(t, qt.IsNil(json.Unmarshal(member, &m)))
	return m
}

// createDCAPI mints one browser-flow session through a Creator pinned to mode,
// with the client policy the caller wants tested.
func createDCAPI(t *testing.T, mode string, pol policy.ClientPolicy) *sessions.Created {
	t.Helper()
	app := verifiercore.TestApp(t)
	created, err := app.SessionCreator().WithDCAPIMode(mode).Create(t.Context(), sessions.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-dcapi-mode",
		Flow: oid4vp.DCAPI, Query: *dcql.PresetPIDFull(), Policy: pol,
		WebhookURL: "https://client.test/hook", ExpectedOrigins: []string{"https://client.test"},
	})
	qt.Assert(t, qt.IsNil(err))
	return created
}

func boolPtr(b bool) *bool { return &b }

// The deployment ceiling decides first, and under the two fixed modes a
// client's own recorded choice changes nothing. That is the whole point of
// calling it a ceiling: a per-client setting may narrow what one client gets,
// never widen what the deployment issues.
func TestDCAPIModeCeilingOverridesClientPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		policy   policy.ClientPolicy
		protocol string
	}{
		{"signed deployment, client silent", sessions.DCAPIModeSigned, policy.ClientPolicy{}, "openid4vp-v1-signed"},
		{"signed deployment, client asks unsigned", sessions.DCAPIModeSigned,
			policy.ClientPolicy{RequireSignedDCAPIP: boolPtr(false)}, "openid4vp-v1-signed"},
		{"unsigned deployment, client silent", sessions.DCAPIModeUnsigned, policy.ClientPolicy{}, "openid4vp-v1-unsigned"},
		{"unsigned deployment, client asks signed", sessions.DCAPIModeUnsigned,
			policy.ClientPolicy{RequireSignedDCAPIP: boolPtr(true)}, "openid4vp-v1-unsigned"},
		{"both, client silent", sessions.DCAPIModeBoth, policy.ClientPolicy{}, "openid4vp-v1-signed"},
		{"both, client asks signed", sessions.DCAPIModeBoth,
			policy.ClientPolicy{RequireSignedDCAPIP: boolPtr(true)}, "openid4vp-v1-signed"},
		{"both, client asks unsigned", sessions.DCAPIModeBoth,
			policy.ClientPolicy{RequireSignedDCAPIP: boolPtr(false)}, "openid4vp-v1-unsigned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := createDCAPI(t, tc.mode, tc.policy)
			qt.Assert(t, qt.Equals(decodeMember(t, created.Invocation.DCAPI).Protocol, tc.protocol))
		})
	}
}

// A Creator nobody told about the deployment setting issues signed requests.
// Forgetting to wire a security posture must not drop the layer that lets a
// wallet authenticate us.
func TestDCAPIModeDefaultsToSigned(t *testing.T) {
	app := verifiercore.TestApp(t)
	qt.Assert(t, qt.Equals(app.SessionCreator().EffectiveDCAPIMode(), sessions.DCAPIModeSigned))

	created, err := app.SessionCreator().Create(t.Context(), sessions.CreateInput{
		ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-default",
		Flow: oid4vp.DCAPI, Query: *dcql.PresetPIDFull(),
		Policy:     policy.ClientPolicy{RequireSignedDCAPIP: boolPtr(false)},
		WebhookURL: "https://client.test/hook", ExpectedOrigins: []string{"https://client.test"},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(decodeMember(t, created.Invocation.DCAPI).Protocol, "openid4vp-v1-signed"))
}

// What actually differs on the wire. The signed member is a single signed
// token; the unsigned one is the plain request parameters with our client_id
// and expected_origins absent — the wallet is told who to talk to by the
// browser's origin and nothing else ([OID4VP §A.2]).
func TestUnsignedMemberCarriesNoVerifierIdentity(t *testing.T) {
	signed := decodeMember(t, createDCAPI(t, sessions.DCAPIModeSigned, policy.ClientPolicy{}).Invocation.DCAPI)
	qt.Assert(t, qt.IsTrue(signed.Data.Request != ""))
	qt.Assert(t, qt.Equals(signed.Data.ClientID, "")) // inside the signed token, not beside it
	qt.Assert(t, qt.Equals(len(signed.Data.ExpectedOrigins), 0))

	unsigned := decodeMember(t, createDCAPI(t, sessions.DCAPIModeUnsigned,
		policy.ClientPolicy{}).Invocation.DCAPI)
	qt.Assert(t, qt.Equals(unsigned.Data.Request, ""))
	qt.Assert(t, qt.Equals(unsigned.Data.ClientID, ""))
	qt.Assert(t, qt.Equals(len(unsigned.Data.ExpectedOrigins), 0))
	// It is a real request all the same: the parameters are there, unwrapped.
	qt.Assert(t, qt.IsTrue(unsigned.Data.Nonce != ""))
}

// The session keeps its expected origins under an unsigned request even though
// the wallet is never told them. The origin check made when the response comes
// back is ours and is required regardless of what the wallet was asked to do
// ([OID4VP §14.9]) — dropping it with the signature would turn an unsigned
// deployment into an unprotected one.
func TestUnsignedStillBindsExpectedOriginsServerSide(t *testing.T) {
	app := verifiercore.TestApp(t)
	created, err := app.SessionCreator().WithDCAPIMode(sessions.DCAPIModeUnsigned).
		Create(t.Context(), sessions.CreateInput{
			ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-origins",
			Flow: oid4vp.DCAPI, Query: *dcql.PresetPIDFull(), Policy: policy.ClientPolicy{},
			WebhookURL: "https://client.test/hook", ExpectedOrigins: []string{"https://client.test"},
		})
	qt.Assert(t, qt.IsNil(err))

	sess, err := app.Sessions().Load(t.Context(), created.SessionID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(sess.ExpectedOrigins, []string{"https://client.test"}))
}

// Only the browser flow is affected. A QR or same-device session is built the
// same way whatever the browser-request setting says, because neither has a
// request member to sign or leave unsigned.
func TestDCAPIModeLeavesOtherFlowsAlone(t *testing.T) {
	for _, flow := range []oid4vp.Flow{oid4vp.CrossDevice, oid4vp.SameDevice} {
		app := verifiercore.TestApp(t)
		in := sessions.CreateInput{
			ClientID: "01JZXCLIENT000000000000001", CorrelationID: "corr-other-flow",
			Flow: flow, Query: *dcql.PresetPIDFull(),
			Policy:     policy.ClientPolicy{RequireSignedDCAPIP: boolPtr(false)},
			WebhookURL: "https://client.test/hook",
		}
		if flow == oid4vp.SameDevice {
			in.RedirectURI = "https://client.test/done"
		}
		created, err := app.SessionCreator().WithDCAPIMode(sessions.DCAPIModeUnsigned).
			Create(t.Context(), in)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(len(created.Invocation.DCAPI), 0))
		qt.Assert(t, qt.IsTrue(created.Invocation.SchemeURI != ""))
	}
}
