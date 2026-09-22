package testwallet

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// pkiWire is the PEM-string projection of a PKI. It exists so one process can
// persist the freshly built issuance PKI to disk and a SEPARATE process can
// reload the SAME keys — credentials issued by the second process must chain to
// the IACA root the first process placed in
// the trust cache. Certificates are PEM "CERTIFICATE" blocks; private keys are
// PKCS#8 "PRIVATE KEY" blocks. No attribute values ride through this file — it
// carries only key and certificate material.
type pkiWire struct {
	IACARoot   string `json:"iaca_root"`
	IACAKey    string `json:"iaca_key"`
	DSCert     string `json:"ds_cert"`
	DSKey      string `json:"ds_key"`
	StatusCert string `json:"status_cert"`
	StatusKey  string `json:"status_key"`
	RogueRoot  string `json:"rogue_root"`
	RogueCert  string `json:"rogue_cert"`
	RogueKey   string `json:"rogue_key"`
	DeviceKey  string `json:"device_key"`
}

// MarshalJSON serializes the PKI to the PEM-string wire form (perf reuse).
func (p *PKI) MarshalJSON() ([]byte, error) {
	keyPEM := func(k *ecdsa.PrivateKey) (string, error) {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
	}
	certPEM := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	var w pkiWire
	var err error
	w.IACARoot = certPEM(p.IACARoot)
	if w.IACAKey, err = keyPEM(p.IACAKey); err != nil {
		return nil, err
	}
	w.DSCert = certPEM(p.DSCert)
	if w.DSKey, err = keyPEM(p.DSKey); err != nil {
		return nil, err
	}
	w.StatusCert = certPEM(p.StatusCert)
	if w.StatusKey, err = keyPEM(p.StatusKey); err != nil {
		return nil, err
	}
	w.RogueRoot = certPEM(p.RogueRoot)
	w.RogueCert = certPEM(p.RogueCert)
	if w.RogueKey, err = keyPEM(p.RogueKey); err != nil {
		return nil, err
	}
	if w.DeviceKey, err = keyPEM(p.DeviceKey); err != nil {
		return nil, err
	}
	return json.Marshal(w)
}

// UnmarshalPKI rebuilds a PKI from the MarshalJSON wire form.
func UnmarshalPKI(b []byte) (*PKI, error) {
	var w pkiWire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	parseCert := func(s string) (*x509.Certificate, error) {
		blk, _ := pem.Decode([]byte(s))
		if blk == nil {
			return nil, fmt.Errorf("testwallet: not a PEM certificate")
		}
		return x509.ParseCertificate(blk.Bytes)
	}
	parseKey := func(s string) (*ecdsa.PrivateKey, error) {
		blk, _ := pem.Decode([]byte(s))
		if blk == nil {
			return nil, fmt.Errorf("testwallet: not a PEM private key")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("testwallet: not an EC private key")
		}
		return ec, nil
	}
	p := &PKI{}
	var err error
	if p.IACARoot, err = parseCert(w.IACARoot); err != nil {
		return nil, err
	}
	if p.IACAKey, err = parseKey(w.IACAKey); err != nil {
		return nil, err
	}
	if p.DSCert, err = parseCert(w.DSCert); err != nil {
		return nil, err
	}
	if p.DSKey, err = parseKey(w.DSKey); err != nil {
		return nil, err
	}
	if p.StatusCert, err = parseCert(w.StatusCert); err != nil {
		return nil, err
	}
	if p.StatusKey, err = parseKey(w.StatusKey); err != nil {
		return nil, err
	}
	if p.RogueRoot, err = parseCert(w.RogueRoot); err != nil {
		return nil, err
	}
	if p.RogueCert, err = parseCert(w.RogueCert); err != nil {
		return nil, err
	}
	if p.RogueKey, err = parseKey(w.RogueKey); err != nil {
		return nil, err
	}
	if p.DeviceKey, err = parseKey(w.DeviceKey); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadPKI reads and rebuilds a PKI persisted by MarshalJSON.
func LoadPKI(path string) (*PKI, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied perf fixture path
	if err != nil {
		return nil, err
	}
	return UnmarshalPKI(b)
}
