package configbundle

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// deterministicSeed returns a fixed Ed25519 private key for
// reproducible test signatures.
func deterministicSeed(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// sampleBundle is the kind of payload a wizard would marshal: a few
// scalar fields, one nested object, one array, plus the
// *BundleSignature root field that gets populated by Sign.
type sampleBundle struct {
	BundleType string `json:"bundle_type"`
	BundleID   string `json:"bundle_id"`
	Identity   struct {
		LegalName string `json:"legal_name"`
		Country   string `json:"country"`
	} `json:"identity"`
	Caps            []string         `json:"caps"`
	BundleSignature *BundleSignature `json:"bundle_signature,omitempty"`
}

func newSample() sampleBundle {
	b := sampleBundle{
		BundleType: "test.v1",
		BundleID:   "rt-1",
		Caps:       []string{"a", "b"},
	}
	b.Identity.LegalName = "Test Co"
	b.Identity.Country = "GBR"
	return b
}

func TestSignVerify_Roundtrip(t *testing.T) {
	priv := deterministicSeed(t)
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	signed, sig, err := Sign(newSample(), priv, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig.SignerPubkey == "" || sig.Signature == "" {
		t.Fatalf("empty signature fields: %+v", sig)
	}
	if sig.SignedAt != now.UnixMilli() {
		t.Fatalf("signed_at drift: got %d want %d", sig.SignedAt, now.UnixMilli())
	}
	if !strings.Contains(string(signed), `"bundle_signature"`) {
		t.Fatalf("signed bundle missing signature block: %s", signed)
	}
	digest, err := Verify(signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if digest == "" {
		t.Fatalf("empty digest")
	}
}

func TestVerify_RejectsTampered(t *testing.T) {
	priv := deterministicSeed(t)
	signed, _, err := Sign(newSample(), priv, time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tampered := []byte(strings.Replace(string(signed), "Test Co", "Evil Corp", 1))
	if _, err := Verify(tampered); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("verify accepted tampered bundle (or wrong error): %v", err)
	}
}

func TestVerify_UnsignedBundleRejected(t *testing.T) {
	raw, _ := json.Marshal(newSample())
	_, err := Verify(raw)
	if !errors.Is(err, ErrUnsigned) {
		t.Fatalf("got %v want ErrUnsigned", err)
	}
}

func TestSign_RejectsShortKey(t *testing.T) {
	short := ed25519.PrivateKey(make([]byte, 16))
	if _, _, err := Sign(newSample(), short, time.Now()); err == nil {
		t.Fatalf("expected error for short key")
	}
}

func TestParseSeed_AcceptsBothLengths(t *testing.T) {
	priv := deterministicSeed(t)
	const hexAlphabet = "0123456789abcdef"
	encode := func(b []byte) string {
		out := make([]byte, len(b)*2)
		for i, x := range b {
			out[i*2] = hexAlphabet[x>>4]
			out[i*2+1] = hexAlphabet[x&0x0f]
		}
		return string(out)
	}
	if got, err := ParseSeed(encode(priv.Seed())); err != nil || len(got) != ed25519.PrivateKeySize {
		t.Fatalf("32-byte seed: err=%v len=%d", err, len(got))
	}
	if got, err := ParseSeed(encode(priv)); err != nil || len(got) != ed25519.PrivateKeySize {
		t.Fatalf("64-byte full key: err=%v len=%d", err, len(got))
	}
	if _, err := ParseSeed("not-hex"); err == nil {
		t.Fatalf("expected error for non-hex input")
	}
	if _, err := ParseSeed("aabbcc"); err == nil {
		t.Fatalf("expected error for wrong-length input")
	}
}

func TestBase58_RoundtripVectors(t *testing.T) {
	cases := [][]byte{
		[]byte("hello"),
		{0, 0, 1, 2, 3},
		{0xff, 0x00, 0xff},
		make([]byte, 32),
	}
	for _, c := range cases {
		enc := EncodeBase58(c)
		dec, err := DecodeBase58(enc)
		if err != nil {
			t.Fatalf("decode %x: %v", c, err)
		}
		if string(dec) != string(c) {
			t.Fatalf("roundtrip drift: in=%x out=%x", c, dec)
		}
	}
}

func TestBase58_RejectsInvalidChar(t *testing.T) {
	if _, err := DecodeBase58("0OIl"); err == nil {
		t.Fatalf("expected error for non-alphabet char")
	}
}

func TestGenerateSigningKey_Length(t *testing.T) {
	priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key length wrong: got %d want %d", len(priv), ed25519.PrivateKeySize)
	}
}
