package keyspace_test

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/dativa-lv/eudi-verifier-core/internal/keyspace"
)

func TestNewNormalizes(t *testing.T) {
	qt.Assert(t, qt.Equals(keyspace.New(""), keyspace.Prefix("")))
	qt.Assert(t, qt.Equals(keyspace.New("  "), keyspace.Prefix("")))
	qt.Assert(t, qt.Equals(keyspace.New("verifierdev"), keyspace.Prefix("verifierdev:")))
	qt.Assert(t, qt.Equals(keyspace.New("verifierdev:"), keyspace.Prefix("verifierdev:")))
	qt.Assert(t, qt.Equals(keyspace.New("a:b"), keyspace.Prefix("a:b:")))
}

func TestKey(t *testing.T) {
	qt.Assert(t, qt.Equals(keyspace.New("").Key("vc:session:1"), "vc:session:1"))
	qt.Assert(t, qt.Equals(keyspace.New("verifierdev").Key("vc:session:1"), "verifierdev:vc:session:1"))
}
