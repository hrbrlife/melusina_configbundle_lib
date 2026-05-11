package configbundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// goldenFixture is the canonical wizard-family payload used by every
// configurator's CI to detect canonical-form drift. The exact byte
// shape is pinned below: canonical-bytes hex, canonical SHA-256, and
// the base58 signature produced by the deterministic seed.
//
// HOW TO READ A FAILURE:
//
//  * If `gotCanonicalHex != goldenCanonicalHex` someone changed the
//    canonical encoder (key sorting, whitespace, escaping, number
//    rendering). The constellation's signature pipeline is broken
//    until every downstream verifier picks up the same change.
//
//  * If only `gotSigBase58 != goldenSigBase58` then the canonical
//    bytes match but the Ed25519 primitive or the base58 alphabet
//    changed. Same downstream-break severity.
//
// HOW TO UPDATE: re-run this test, copy the printed actual values
// into the constants, and commit the change ALONGSIDE the matching
// change in every wizard repo. The fixture is intentionally a
// tripwire — propagate or revert; don't bypass.
const (
	// Deterministic Ed25519 seed: 32 bytes [1, 2, …, 32]. Matches
	// every wizard test's seeding pattern so signatures reproduce
	// byte-for-byte across repos.
	goldenSeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	// SignedAt epoch (ms) — pinned so the signature is reproducible.
	goldenSignedAtMs = int64(1700000000000)

	// Canonical-bytes string form (post-bundle_signature-strip,
	// sorted keys, no whitespace). Pinned both as the literal JSON
	// string AND as a hex byte string so a binary diff is
	// unambiguous in CI logs.
	goldenCanonicalString = `{"bundle_id":"golden-1","bundle_type":"golden.v1","caps":["ccash","station"],"identity":{"country":"GBR","legal_name":"Melusina Test Co"},"version":1}`

	goldenCanonicalHex = "7b2262756e646c655f6964223a22676f6c64656e2d31222c2262756e646c655f74797065223a22676f6c64656e2e7631222c2263617073223a5b226363617368222c2273746174696f6e225d2c226964656e74697479223a7b22636f756e747279223a22474252222c226c6567616c5f6e616d65223a224d656c7573696e61205465737420436f227d2c2276657273696f6e223a317d"

	// SHA-256 of the canonical bytes, hex. The compact "digest"
	// every verifier stamps into its receipt.
	goldenCanonicalSHA256 = "15856070c2fdb9d7b622d4f38004640084549c615cc32d70b167ddd7685cad0d"

	// Base58 of the signer pubkey produced by ed25519.NewKeyFromSeed
	// over goldenSeedHex.
	goldenSignerBase58 = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj"

	// Base58 of the detached signature produced by signing
	// goldenCanonicalHex with the goldenSeed key.
	goldenSigBase58 = "3nD73qWETSwbHgPybGFrRLk8i2VzHjafcNsNCbx8Ry9JpFB6ChoCY83Bn6qCx1pSYKnhX5PtsBvG6N3ZZFirP3cr"
)

// TestGolden_CanonicalAndSignature is the cross-impl golden fixture.
// Any of the four wizard repos can copy this file in and the test
// will pass iff that repo's canonical encoder + base58 codec + Ed25519
// primitive all agree byte-for-byte with the shared lib.
//
// The fixture self-pins on the first run: it builds the bundle, runs
// the encoder, and compares the canonical bytes + canonical SHA-256
// against the constants above. The signature is regenerated each
// run (deterministic from the seed) and compared against the pinned
// base58 string.
func TestGolden_CanonicalAndSignature(t *testing.T) {
	// Construct the golden payload as a generic JSON object so
	// nothing structural depends on a Go struct definition. This
	// keeps the fixture identical across the four wizard repos
	// (whose Bundle Go types all differ).
	payload := map[string]any{
		"bundle_type": "golden.v1",
		"bundle_id":   "golden-1",
		"version":     json.Number("1"),
		"identity": map[string]any{
			"legal_name": "Melusina Test Co",
			"country":    "GBR",
		},
		"caps": []any{"ccash", "station"},
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	canonical, err := CanonicalizeBundleForSigning(raw, SignatureBlockKey)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(canonical) != goldenCanonicalString {
		t.Fatalf("canonical-string drift:\n  got:  %s\n  want: %s",
			canonical, goldenCanonicalString)
	}
	gotHex := hex.EncodeToString(canonical)
	if gotHex != goldenCanonicalHex {
		t.Fatalf("canonical-bytes drift:\n  got:  %s\n  want: %s\n(if intentional, update goldenCanonicalHex and propagate to every wizard)",
			gotHex, goldenCanonicalHex)
	}

	sum := sha256.Sum256(canonical)
	gotSHA := hex.EncodeToString(sum[:])
	if gotSHA != goldenCanonicalSHA256 {
		t.Fatalf("canonical SHA-256 drift:\n  got:  %s\n  want: %s",
			gotSHA, goldenCanonicalSHA256)
	}

	seed, err := hex.DecodeString(goldenSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, canonical)

	gotSigner := EncodeBase58(pub)
	if gotSigner != goldenSignerBase58 {
		t.Fatalf("signer pubkey base58 drift:\n  got:  %s\n  want: %s\n(seed: %s)",
			gotSigner, goldenSignerBase58, goldenSeedHex)
	}
	gotSig := EncodeBase58(sig)
	if gotSig != goldenSigBase58 {
		t.Fatalf("signature base58 drift:\n  got:  %s\n  want: %s",
			gotSig, goldenSigBase58)
	}

	// Sanity: build a SignedBundle, round-trip through Verify.
	signed := SignedBundle{
		Payload: json.RawMessage(raw),
		Signature: BundleSignature{
			SignerPubkey: gotSigner,
			Signature:    gotSig,
			SignedAt:     goldenSignedAtMs,
		},
	}
	// Emit the SignedBundle in the wire shape Verify expects: the
	// payload's keys at the root, alongside bundle_signature.
	wire := map[string]any{}
	if err := json.Unmarshal(signed.Payload, &wire); err != nil {
		t.Fatalf("re-decode payload: %v", err)
	}
	wire[SignatureBlockKey] = map[string]any{
		"signer_pubkey": signed.Signature.SignerPubkey,
		"signature":     signed.Signature.Signature,
		"signed_at":     signed.Signature.SignedAt,
	}
	wireRaw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	digest, err := Verify(wireRaw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if digest != goldenCanonicalSHA256 {
		t.Fatalf("digest drift: got %s want %s", digest, goldenCanonicalSHA256)
	}
}
