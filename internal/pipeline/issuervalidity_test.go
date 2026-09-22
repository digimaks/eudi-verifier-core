package pipeline

import (
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

var (
	testNow    = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	testSigned = testNow.Add(-200 * 24 * time.Hour)
)

// The whole point of the model: under the default the path is judged at the
// credential's signing time, so a document signer that has since rotated does
// not fail every wallet; under the strict model it is judged now.
func TestPathValidationTimePerModel(t *testing.T) {
	qt.Check(t, qt.Equals(
		ValidityAtSigningTime.PathValidationTime(testSigned, testNow), testSigned))
	qt.Check(t, qt.Equals(
		ValidityAtCurrentTime.PathValidationTime(testSigned, testNow), testNow))
}

// A credential that carries no signing time falls back to the current time even
// under the signing-time model: a validity window cannot be relaxed using a time
// we do not have, so the fallback is the stricter of the two, never the looser.
func TestPathValidationTimeFallsBackToNowWithoutASigningTime(t *testing.T) {
	qt.Check(t, qt.Equals(
		ValidityAtSigningTime.PathValidationTime(time.Time{}, testNow), testNow))
	qt.Check(t, qt.IsFalse(ValidityAtSigningTime.SigningTimeUsed(time.Time{})))
	qt.Check(t, qt.IsTrue(ValidityAtSigningTime.SigningTimeUsed(testSigned)))
	qt.Check(t, qt.IsFalse(ValidityAtCurrentTime.SigningTimeUsed(testSigned)))
}

// An unset model must not resolve to the permissive posture by accident: the
// zero value behaves as the strict one.
func TestUnsetModelIsStrict(t *testing.T) {
	var unset IssuerValidityModel
	qt.Check(t, qt.Equals(unset.PathValidationTime(testSigned, testNow), testNow))
}
