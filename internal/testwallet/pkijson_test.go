package testwallet

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// TestPKIMarshalRoundTrip proves the PEM projection used to hand a PKI between
// the perf seed and loadgen processes preserves every key and certificate: the
// reloaded PKI must be byte-identical in cert DER and key material so credentials
// issued by loadgen still chain to the anchor the seeder cached.
func TestPKIMarshalRoundTrip(t *testing.T) {
	p := NewPKI(t)

	b, err := p.MarshalJSON()
	qt.Assert(t, qt.IsNil(err))

	got, err := UnmarshalPKI(b)
	qt.Assert(t, qt.IsNil(err))

	// Certificates: compare raw DER.
	qt.Check(t, qt.IsTrue(got.IACARoot.Equal(p.IACARoot)))
	qt.Check(t, qt.IsTrue(got.DSCert.Equal(p.DSCert)))
	qt.Check(t, qt.IsTrue(got.StatusCert.Equal(p.StatusCert)))
	qt.Check(t, qt.IsTrue(got.RogueRoot.Equal(p.RogueRoot)))
	qt.Check(t, qt.IsTrue(got.RogueCert.Equal(p.RogueCert)))

	// Private keys: compare the scalar D and public point.
	qt.Check(t, qt.IsTrue(got.IACAKey.Equal(p.IACAKey)))
	qt.Check(t, qt.IsTrue(got.DSKey.Equal(p.DSKey)))
	qt.Check(t, qt.IsTrue(got.StatusKey.Equal(p.StatusKey)))
	qt.Check(t, qt.IsTrue(got.RogueKey.Equal(p.RogueKey)))
	qt.Check(t, qt.IsTrue(got.DeviceKey.Equal(p.DeviceKey)))
}
