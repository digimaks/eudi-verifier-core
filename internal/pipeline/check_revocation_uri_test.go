package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	sdjwt "github.com/gmb-eudi/go-sdjwt"
	statuslist "github.com/gmb-eudi/go-statuslist"

	"github.com/go-quicktest/qt"
)

// unreachableList is a status-list fetcher that always fails, standing in for
// the whole family of reasons a list cannot be read (no route, no name, a
// refused connection, a 404). What matters for these tests is only that the
// check ends up unable to resolve a status.
type unreachableList struct{ err error }

func (f unreachableList) Get(context.Context, string) ([]byte, error) { return nil, f.err }

// statusIndex is deliberately distinctive: every test below asserts it appears
// NOWHERE in the report, so a stray occurrence cannot be mistaken for
// something else's number.
const statusIndex = 918273

func credentialWithStatus(uri string) *Credential {
	return &Credential{SD: &sdjwt.VerifiedCredential{
		VCT:    "urn:eu.europa.ec.eudi:pid:1",
		Status: &sdjwt.StatusRef{URI: uri, Index: statusIndex},
	}}
}

func unresolvableStatusContext(t *testing.T, uri string) *PipelineContext {
	t.Helper()
	pc := NewContext("01JZXSESSION", nil, nil)
	pc.Status = statuslist.NewChecker(unreachableList{err: errors.New("dial: no route to host")}, nil)
	pc.Credentials = []*Credential{credentialWithStatus(uri)}
	return pc
}

// An operator reading a failed verification needs to know WHICH list could not
// be resolved: the error text underneath names a cause ("resource not found",
// "context deadline exceeded") without naming the address it was talking to.
// So the failing check carries the list URI.
func TestRevocationFailureNamesTheList(t *testing.T) {
	const uri = "https://status.example/statuslist/lv/pid/abc123"

	res, err := Revocation().Run(context.Background(), unresolvableStatusContext(t, uri))

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.Outcome, OutcomeFail))
	qt.Assert(t, qt.Equals(res.Code, "err:revocation:unavailable"))
	qt.Assert(t, qt.Equals(res.StatusListURI, uri))
	// The cause is the library's own sentinel text, kept verbatim so it can be
	// read against that library's error list.
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(res.Detail, "statuslist: status list could not be fetched")))
}

// The list URI is shared by every credential on that list; the entry index
// inside it identifies ONE holder's credential. So the URI may be recorded and
// the index may not — a diagnostic must not become a correlatable handle.
// Asserted on the serialized report, which is what is persisted, logged from
// and served.
func TestRevocationFailureNeverRecordsTheIndex(t *testing.T) {
	const uri = "https://status.example/statuslist/lv/pid/abc123"

	pc := unresolvableStatusContext(t, uri)
	res, err := Revocation().Run(context.Background(), pc)
	qt.Assert(t, qt.IsNil(err))

	pc.Report.Add(res)
	raw, merr := json.Marshal(pc.Report.Build())
	qt.Assert(t, qt.IsNil(merr))

	body := string(raw)
	qt.Assert(t, qt.StringContains(body, uri))
	qt.Assert(t, qt.Not(qt.StringContains(body, strconv.Itoa(statusIndex))))
	// Nor under any name: the report type has no field for it at all, and this
	// pins that it stays that way.
	qt.Assert(t, qt.Not(qt.StringContains(body, "index")))
	qt.Assert(t, qt.Not(qt.StringContains(body, "idx")))
}

// A credential that references no status list must not acquire a URI field:
// absent, never an empty string, so a reader can tell "no list" from "a list
// we could not name".
func TestRevocationWithoutStatusRefCarriesNoURI(t *testing.T) {
	pc := NewContext("01JZXSESSION", nil, nil)
	pc.Status = statuslist.NewChecker(unreachableList{err: errors.New("unused")}, nil)
	pc.Credentials = []*Credential{{SD: &sdjwt.VerifiedCredential{VCT: "urn:eu.europa.ec.eudi:pid:1"}}}

	res, err := Revocation().Run(context.Background(), pc)

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.Outcome, OutcomePass))
	qt.Assert(t, qt.Equals(res.StatusListURI, ""))

	pc.Report.Add(res)
	raw, merr := json.Marshal(pc.Report.Build())
	qt.Assert(t, qt.IsNil(merr))
	qt.Assert(t, qt.Not(qt.StringContains(string(raw), "status_list_uri")))
}
