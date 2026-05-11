package configbundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// SignatureBlockKey is the JSON root key used by the wizard family
// (partneroorg, vintageconfig, cybertellerconfig) to embed their
// detached signature block. Exported as a constant so callers don't
// retype the literal.
const SignatureBlockKey = "bundle_signature"

// BundleSignature is the detached signature block embedded into the
// signed bundle alongside the operator-supplied configuration. The
// JSON shape is wire-stable; downstream consumers script against it.
type BundleSignature struct {
	SignerPubkey string `json:"signer_pubkey"`
	Signature    string `json:"signature"`
	SignedAt     int64  `json:"signed_at"`
}

// SignedBundle is a self-describing on-wire artefact pairing a
// generic JSON payload with its detached BundleSignature. Used by
// the cross-impl golden fixture so any wizard's canonical encoder
// can be regression-tested against a pinned digest.
type SignedBundle struct {
	Payload   json.RawMessage `json:"payload"`
	Signature BundleSignature `json:"bundle_signature"`
}

// Sign marshals bundle to JSON, computes canonical bytes (stripping
// SignatureBlockKey), signs them with priv, and returns the signed
// bundle bytes (pretty-printed, with bundle_signature inlined at the
// root) plus the BundleSignature struct.
//
// bundle MUST be a Go value whose `json.Marshal` output is a JSON
// object with the signature block addressable as the root key
// "bundle_signature" (omitempty + a *BundleSignature pointer is the
// idiomatic shape — see any of the migrated wizards for examples).
func Sign(bundle any, priv ed25519.PrivateKey, now time.Time) ([]byte, BundleSignature, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, BundleSignature{}, fmt.Errorf("configbundle: private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv))
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, BundleSignature{}, fmt.Errorf("configbundle: marshal bundle: %w", err)
	}
	canonical, err := CanonicalizeBundleForSigning(raw, SignatureBlockKey)
	if err != nil {
		return nil, BundleSignature{}, err
	}
	sig := ed25519.Sign(priv, canonical)
	pub := priv.Public().(ed25519.PublicKey)
	bs := BundleSignature{
		SignerPubkey: EncodeBase58(pub),
		Signature:    EncodeBase58(sig),
		SignedAt:     now.UnixMilli(),
	}

	// Re-decode raw → generic, inject the signature block, and re-emit
	// pretty JSON. This avoids requiring the caller's bundle type to
	// expose a *BundleSignature field by name (works equally well for
	// types that have one and types that don't).
	var generic map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, BundleSignature{}, fmt.Errorf("configbundle: re-decode bundle: %w", err)
	}
	generic[SignatureBlockKey] = map[string]any{
		"signer_pubkey": bs.SignerPubkey,
		"signature":     bs.Signature,
		"signed_at":     json.Number(fmt.Sprintf("%d", bs.SignedAt)),
	}
	out, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		return nil, BundleSignature{}, fmt.Errorf("configbundle: marshal signed bundle: %w", err)
	}
	return out, bs, nil
}

// Verify parses the bundle bytes, recanonicalises them (stripping
// SignatureBlockKey), and verifies the embedded Ed25519 signature.
// Returns the canonical-bytes SHA-256 digest (hex) on success — the
// same digest signers can stamp into receipts.
func Verify(rawBundleJSON []byte) (string, error) {
	var generic map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawBundleJSON))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return "", fmt.Errorf("configbundle: parse bundle: %w", err)
	}
	sigAny, ok := generic[SignatureBlockKey]
	if !ok || sigAny == nil {
		return "", ErrUnsigned
	}
	sigMap, ok := sigAny.(map[string]any)
	if !ok {
		return "", fmt.Errorf("configbundle: %s is not an object", SignatureBlockKey)
	}
	pubStr, _ := sigMap["signer_pubkey"].(string)
	sigStr, _ := sigMap["signature"].(string)
	if pubStr == "" || sigStr == "" {
		return "", ErrUnsigned
	}
	pub, err := DecodeBase58(pubStr)
	if err != nil {
		return "", fmt.Errorf("configbundle: decode signer pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("configbundle: signer pubkey must be %d bytes, got %d",
			ed25519.PublicKeySize, len(pub))
	}
	sig, err := DecodeBase58(sigStr)
	if err != nil {
		return "", fmt.Errorf("configbundle: decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("configbundle: signature must be %d bytes, got %d",
			ed25519.SignatureSize, len(sig))
	}
	canonical, err := CanonicalizeBundleForSigning(rawBundleJSON, SignatureBlockKey)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return "", ErrSignatureInvalid
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// GenerateSigningKey produces a fresh Ed25519 keypair using crypto/rand.
// Used by every wizard's "no operator seed supplied" path.
func GenerateSigningKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("configbundle: generate keypair: %w", err)
	}
	return priv, nil
}

// ParseSeed accepts either a 64-byte hex full Ed25519 private key or
// a 32-byte hex seed and returns an ed25519.PrivateKey. The wizards
// expose this as the operator-supplied seed entry path.
func ParseSeed(hexStr string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("configbundle: decode hex seed: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("configbundle: seed must be %d or %d bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}
