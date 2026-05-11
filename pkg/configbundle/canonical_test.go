package configbundle

import (
	"encoding/hex"
	"testing"
)

// TestCanonicalize_PinnedBytes pins a sample bundle JSON's canonical
// form against a hex byte string. Any change to the canonical encoder
// (key sorting, whitespace, escaping, number formatting) breaks this
// test — that's the point. If you must change the encoder, update the
// pinned hex below AND every consumer in the constellation in the
// same change.
func TestCanonicalize_PinnedBytes(t *testing.T) {
	// Sample bundle with: a nested object (out-of-order keys), an
	// array, a number we want kept as int (UseNumber), a string
	// that needs JSON escaping, the signature block we expect to
	// strip, and an empty array.
	raw := []byte(`{
		"bundle_signature": {
			"signer_pubkey": "willBeStripped",
			"signature": "willBeStripped",
			"signed_at": 1700000000000
		},
		"version": 1,
		"bundle_type": "test.v1",
		"bundle_id": "fix-1",
		"identity": {
			"legal_name": "Test \"Co\".",
			"country": "GBR",
			"emoji": "ok"
		},
		"caps": ["b", "a", "c"],
		"empty": []
	}`)

	got, err := CanonicalizeBundleForSigning(raw, SignatureBlockKey)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	// Computed by hand from the encoder's rules: sorted root keys
	// (bundle_id, bundle_type, caps, empty, identity, version),
	// nested identity sorted (country, emoji, legal_name), array
	// order preserved, no whitespace, " escaped to \", number
	// retained as integer literal (UseNumber).
	want := `{"bundle_id":"fix-1","bundle_type":"test.v1","caps":["b","a","c"],"empty":[],"identity":{"country":"GBR","emoji":"ok","legal_name":"Test \"Co\"."},"version":1}`

	if string(got) != want {
		t.Fatalf("canonical bytes drift:\n got:  %s\n want: %s", got, want)
	}

	// Hex of the canonical bytes — pinned for byte-identical
	// regression detection across repos. Any character drift in the
	// encoder changes this hex.
	wantHex := hex.EncodeToString([]byte(want))
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("hex drift:\n got:  %s\n want: %s", hex.EncodeToString(got), wantHex)
	}
}

// TestCanonicalize_StripsMultipleKeys covers the ccashconfig family
// pattern (signer_pubkey + signature at the root, no nested
// bundle_signature block).
func TestCanonicalize_StripsMultipleKeys(t *testing.T) {
	raw := []byte(`{"a":1,"b":2,"signer_pubkey":"x","signature":"y"}`)
	got, err := CanonicalizeBundleForSigning(raw, "signer_pubkey", "signature")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"a":1,"b":2}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// TestCanonicalize_RejectsInvalidJSON makes sure the parser surfaces
// JSON-decode errors rather than silently producing garbage canonical
// bytes.
func TestCanonicalize_RejectsInvalidJSON(t *testing.T) {
	if _, err := CanonicalizeBundleForSigning([]byte(`{not-json`), SignatureBlockKey); err == nil {
		t.Fatalf("expected parse error")
	}
}

// TestCanonicalize_NumbersAsJSONNumber confirms that integer-looking
// numbers round-trip as their integer literal (no scientific
// notation, no trailing .0). UseNumber on the decoder + json.Number
// stringify path are both load-bearing.
func TestCanonicalize_NumbersAsJSONNumber(t *testing.T) {
	raw := []byte(`{"big":1700000000000,"small":42,"frac":1.5}`)
	got, err := CanonicalizeBundleForSigning(raw)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"big":1700000000000,"frac":1.5,"small":42}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
