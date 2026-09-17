package policy

import (
	"encoding/json"
	"testing"

	"github.com/go-quicktest/qt"
)

// Defaults FAIL CLOSED; every relaxation is an explicit flag
// that surfaces in the verification report.
func TestZeroValueFailsClosed(t *testing.T) {
	var p ClientPolicy
	qt.Assert(t, qt.IsTrue(p.RevocationFailClosed()))
	qt.Assert(t, qt.IsTrue(p.ShortLivedExemption()))
	qt.Assert(t, qt.IsTrue(p.RequireDeviceBindingSDJWT()))
}

func TestExplicitRelaxationsRoundtripJSON(t *testing.T) {
	raw := []byte(`{"revocation_fail_closed":false,"require_device_binding_sdjwt":false}`)
	p, err := Parse(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(p.RevocationFailClosed()))
	qt.Assert(t, qt.IsFalse(p.RequireDeviceBindingSDJWT()))
	qt.Assert(t, qt.IsTrue(p.ShortLivedExemption())) // untouched default

	b, err := json.Marshal(p)
	qt.Assert(t, qt.IsNil(err))
	p2, err := Parse(b)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(p2.RevocationFailClosed()))
}

func TestGarbageRejected(t *testing.T) {
	_, err := Parse([]byte(`{"revocation_fail_closed":"yes"}`))
	qt.Assert(t, qt.IsNotNil(err))
}
