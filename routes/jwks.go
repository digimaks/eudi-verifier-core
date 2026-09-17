package routes

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	verifiercore "github.com/dativa-lv/eudi-verifier-core"

	"azugo.io/azugo"
)

// jwks publishes the operator public keys clients use to verify webhook
// signatures (detached JWS).
// JWK Set per [RFC 7517 §5]; each key's common parameters per [RFC 7517 §4] and
// its EC parameters per [RFC 7518 §6.2] — built from stdlib key parameters; no
// algorithm literals (crv comes from the curve's own canonical name).
func (r *router) jwks(ctx *azugo.Context) {
	keys := make([]map[string]any, 0, 1)
	for _, kid := range []string{verifiercore.KeyWebhookSigning} {
		pub, err := r.Keys().Public(ctx, kid)
		if err != nil {
			ctx.Error(err) // non-wallet endpoint: normal (internal) rendering
			return
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			ctx.Error(fmt.Errorf("jwks: key %s is not EC", kid))
			return
		}
		// Read the coordinates via crypto/ecdh (uncompressed SEC1 point
		// 0x04||X||Y) rather than the deprecated ecdsa.PublicKey.X/Y fields
		// (Go 1.26 SA1019) — same approach as go-oid4vp's ephemeralJWK.
		ep, err := ec.ECDH()
		if err != nil {
			ctx.Error(fmt.Errorf("jwks: key %s: %w", kid, err))
			return
		}
		point := ep.Bytes() // 0x04 || X || Y, each coordinate `size` bytes
		size := (ec.Curve.Params().BitSize + 7) / 8
		if len(point) != 1+2*size {
			ctx.Error(fmt.Errorf("jwks: key %s: unexpected point length %d", kid, len(point)))
			return
		}
		keys = append(keys, map[string]any{
			"kty": "EC",
			"crv": ec.Curve.Params().Name, // "P-256" — curve param name, not an alg literal
			"x":   base64.RawURLEncoding.EncodeToString(point[1 : 1+size]),
			"y":   base64.RawURLEncoding.EncodeToString(point[1+size:]),
			"use": "sig",
			"kid": kid,
		})
	}
	ctx.Header.Set("Cache-Control", "max-age=300")
	ctx.JSON(map[string]any{"keys": keys})
}
