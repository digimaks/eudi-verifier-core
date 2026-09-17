package routes

import (
	"testing"

	verifiercore "github.com/dativa-lv/eudi-verifier-core"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
)

func testApp(tb testing.TB) *azugo.TestApp {
	tb.Helper()
	app := verifiercore.TestApp(tb)
	qt.Assert(tb, qt.IsNil(Init(app)))
	return azugo.NewTestApp(app.App)
}
