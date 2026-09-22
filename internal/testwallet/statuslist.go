package testwallet

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
)

// statusListURI is the single default list this in-memory authority serves.
const statusListURI = "https://status.test/1"

// StatusRef points at one index of one list — mirrors the shape both format
// libs expose (URI + index).
type StatusRef struct {
	URI   string
	Index int
}

// StatusLists is an in-memory Token Status List authority
// (draft-ietf-oauth-status-list, JWT form, bits=1). It implements
// statuslist.Fetcher so unit tests never touch the network.
type StatusLists struct {
	mu      sync.Mutex
	signer  *ecdsa.PrivateKey
	x5c     []*x509.Certificate // status signer chain (leaf first) → trust-layer key resolution
	lists   map[string][]byte   // uri → bit array (1 bit per index, packed LSB-first per [Token Status List §4.1])
	nextIdx map[string]int
	now     func() time.Time
	broken  bool // when set, every Get fails — the revocation-unavailable branch
}

// NewStatusLists returns an authority signing with the PKI's status key and
// carrying the status-signer chain (leaf first) as an x5c header, so the
// verifier pipeline can resolve the status-signer key via the trust layer.
func NewStatusLists(pki *PKI) *StatusLists {
	return &StatusLists{
		signer:  pki.StatusKey,
		x5c:     []*x509.Certificate{pki.StatusCert, pki.IACARoot},
		lists:   map[string][]byte{statusListURI: make([]byte, 1024)},
		nextIdx: map[string]int{},
		now:     time.Now,
	}
}

// NewRef allocates a fresh index on the default list.
func (s *StatusLists) NewRef() StatusRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.nextIdx[statusListURI]
	s.nextIdx[statusListURI] = idx + 1
	return StatusRef{URI: statusListURI, Index: idx}
}

// Revoke sets the bit (status value 1 = INVALID per [Token Status List §7.1]).
func (s *StatusLists) Revoke(ref StatusRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if list, ok := s.lists[ref.URI]; ok && ref.Index/8 < len(list) {
		list[ref.Index/8] |= 1 << (ref.Index % 8)
	}
}

// Break makes every subsequent fetch fail — the revocation-unavailable branch
// (fail-closed default / explicit fail-open). It affects only the
// verifier's fetch (statuslist.Fetcher.Get): the wallet allocates and embeds
// status refs at issuance without fetching, so a broken authority still
// produces a well-formed credential whose status merely cannot be resolved.
func (s *StatusLists) Break() { s.mu.Lock(); s.broken = true; s.mu.Unlock() }

// Get implements statuslist.Fetcher: returns the signed status list token for
// the URI (status list token per [Token Status List §5.1]; sub MUST equal the list URI).
func (s *StatusLists) Get(_ context.Context, url string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken {
		return nil, fmt.Errorf("testwallet: status list source broken")
	}
	bits, ok := s.lists[url]
	if !ok {
		return nil, fmt.Errorf("testwallet: unknown status list %q", url)
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(bits); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	claims, err := json.Marshal(map[string]any{
		"sub": url,
		"iat": s.now().Unix(),
		"exp": s.now().Add(time.Hour).Unix(),
		"ttl": 300,
		"status_list": map[string]any{
			"bits": 1,
			"lst":  base64.RawURLEncoding.EncodeToString(buf.Bytes()),
		},
	})
	if err != nil {
		return nil, err
	}
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"status": s.signer})
	// x5c lets the pipeline resolve the status signer via the trust layer
	// (statuslist.CheckInput.IssuerKeyResolver → trust.ResolveIssuerKey).
	// SignJWS accepts x5c as []*x509.Certificate (leaf first) and serializes it
	// per [RFC 7515 §4.1.6].
	return crypto.SignJWS(context.Background(), kp, "status",
		map[string]any{"typ": "statuslist+jwt", "x5c": s.x5c}, claims)
}
