// Package testwallet simulates an EUDI wallet against eudi-verifier-core using the
// SD-JWT/mdoc Issue façades and a self-contained test PKI. It exists so every
// pipeline check is demonstrably fail-able.
//
// The package is deliberately framework-free: it imports the
// gmb-eudi/go-* format+crypto+trust libraries and the standard library only —
// never Azugo or go-platform-kit. All key, salt, and nonce material comes from
// crypto/rand (never math/rand).
package testwallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
)

// PKI is the self-contained issuance PKI: an IACA-style root, a document
// signer (mdoc DS + SD-JWT issuer), a status-list signer, a rogue chain that
// is NOT in the anchor set (unregistered-issuer fault), and the wallet device
// key.
type PKI struct {
	IACARoot *x509.Certificate
	IACAKey  *ecdsa.PrivateKey

	DSCert *x509.Certificate // issues mdocs AND SD-JWT VCs in this harness
	DSKey  *ecdsa.PrivateKey

	StatusCert *x509.Certificate
	StatusKey  *ecdsa.PrivateKey

	RogueRoot *x509.Certificate
	RogueCert *x509.Certificate
	RogueKey  *ecdsa.PrivateKey

	DeviceKey *ecdsa.PrivateKey // wallet holder/device binding key
}

// BuildPKI builds a fresh, self-consistent test PKI. The DS and status-signer
// leaves chain to the IACA root; the rogue leaf chains to an unrelated root
// that is never placed in the anchor set.
func BuildPKI() (*PKI, error) {
	p := &PKI{}
	var err error
	if p.IACAKey, p.IACARoot, err = selfSignedCA("EUDI Test IACA"); err != nil {
		return nil, err
	}
	if p.DSKey, p.DSCert, err = leaf("EUDI Test DS", p.IACARoot, p.IACAKey); err != nil {
		return nil, err
	}
	if p.StatusKey, p.StatusCert, err = leaf("EUDI Test Status Signer", p.IACARoot, p.IACAKey); err != nil {
		return nil, err
	}
	if p.RogueKey, p.RogueRoot, err = selfSignedCA("Rogue Root"); err != nil {
		return nil, err
	}
	var rogueLeafKey *ecdsa.PrivateKey
	if rogueLeafKey, p.RogueCert, err = leaf("Rogue DS", p.RogueRoot, p.RogueKey); err != nil {
		return nil, err
	}
	p.RogueKey = rogueLeafKey
	if p.DeviceKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}
	return p, nil
}

// NewPKI builds a PKI or fails the test — the ergonomic constructor for tests.
func NewPKI(tb testing.TB) *PKI {
	tb.Helper()
	p, err := BuildPKI()
	if err != nil {
		tb.Fatalf("testwallet: build PKI: %v", err)
	}
	return p
}

// Anchors returns the trust anchors the verifier must be seeded with so the
// harness's credentials verify: the IACA root as PID provider (covers the PID
// preset doctype/vct used in tests), as wallet-provider stand-in, and as PID
// status-signer anchor (the harness's status cert chains to
// the IACA root, so seeding pid_provider_status exercises the *_status-first
// resolution path; omit it to instead exercise the issuer-anchor fallback).
func (p *PKI) Anchors() []trust.Anchor {
	valid := time.Now().Add(24 * time.Hour)
	return []trust.Anchor{
		{Cert: p.IACARoot, Type: trust.PIDProvider, Country: "UT", Status: "granted", ValidUntil: valid, TLSequence: 1},
		{Cert: p.IACARoot, Type: trust.WalletProvider, Country: "UT", Status: "granted", ValidUntil: valid, TLSequence: 1},
		{Cert: p.IACARoot, Type: trust.PIDProviderStatus, Country: "UT", Status: "granted", ValidUntil: valid, TLSequence: 1},
	}
}

// RogueAnchors intentionally returns nothing — the rogue chain must NOT be
// resolvable; kept as an explicit method so tests read declaratively.
func (p *PKI) RogueAnchors() []trust.Anchor { return nil }

func selfSignedCA(cn string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Country: []string{"UT"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, err
}

func leaf(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Country: []string{"UT"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf: %w", err)
	}
	return key, cert, nil
}

// randSerial draws a positive 128-bit certificate serial from crypto/rand, so
// distinct leaves under one CA never collide (never math/rand).
func randSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("testwallet: serial: %w", err)
	}
	return serial.Add(serial, big.NewInt(1)), nil // ensure strictly positive
}
