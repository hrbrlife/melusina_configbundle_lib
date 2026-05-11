// Package configbundle is the shared canonical-JSON + Ed25519 + base58
// primitive used by every Melusina configurator wizard
// (partneroorg, vintageconfig, cybertellerconfig, ccashconfig) and
// the popaye-side apply-ccash-config consumer.
//
// The canonical form is sorted-key JSON over a generic-map round-trip
// with operator-named root keys stripped (typically "bundle_signature"
// for the wizard family, or "signer_pubkey" + "signature" for the
// ccashconfig family). The signature is detached Ed25519 over those
// canonical bytes. The base58 alphabet is the Bitcoin/Solana one —
// the same constant pkg/solana, the Go finreact-sidecar, and the Java
// Gate 2 use. Drift on any of these primitives breaks the whole
// constellation's signature pipeline.
package configbundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalizeBundleForSigning returns the deterministic canonical-JSON
// byte string used by every Ed25519 verifier in the constellation.
// It decodes rawBundleJSON into a generic map (UseNumber so 64-bit
// integers don't lose precision), deletes the listed root-level keys
// (typically the signature block — "bundle_signature" for the wizard
// family, or "signer_pubkey" and "signature" for the ccashconfig
// family), and emits sorted-key JSON with no whitespace.
//
// Byte-for-byte stable. The signature signs over the bytes this
// function returns; the verifier re-runs this function to recompute
// the same bytes.
func CanonicalizeBundleForSigning(rawBundleJSON []byte, stripRootKeys ...string) ([]byte, error) {
	var generic map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawBundleJSON))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("configbundle: parse bundle: %w", err)
	}
	for _, k := range stripRootKeys {
		delete(generic, k)
	}
	var buf bytes.Buffer
	if err := encodeCanonicalJSON(&buf, generic); err != nil {
		return nil, fmt.Errorf("configbundle: canonical encode: %w", err)
	}
	return buf.Bytes(), nil
}

// MarshalCanonical emits canonical JSON for an already-built generic
// value (map[string]any, []any, primitives). Useful when the caller
// has already stripped signature fields and wants to commit to the
// byte form without another marshal round-trip.
func MarshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonicalJSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeCanonicalJSON(w *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		_, err := w.WriteString("null")
		return err
	case bool:
		if val {
			_, err := w.WriteString("true")
			return err
		}
		_, err := w.WriteString("false")
		return err
	case string:
		enc, err := json.Marshal(val)
		if err != nil {
			return err
		}
		_, err = w.Write(enc)
		return err
	case json.Number:
		_, err := w.WriteString(val.String())
		return err
	case float64:
		enc, err := json.Marshal(val)
		if err != nil {
			return err
		}
		_, err = w.Write(enc)
		return err
	case []any:
		if err := w.WriteByte('['); err != nil {
			return err
		}
		for i, item := range val {
			if i > 0 {
				if err := w.WriteByte(','); err != nil {
					return err
				}
			}
			if err := encodeCanonicalJSON(w, item); err != nil {
				return err
			}
		}
		return w.WriteByte(']')
	case map[string]any:
		if err := w.WriteByte('{'); err != nil {
			return err
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				if err := w.WriteByte(','); err != nil {
					return err
				}
			}
			keyEnc, err := json.Marshal(k)
			if err != nil {
				return err
			}
			if _, err := w.Write(keyEnc); err != nil {
				return err
			}
			if err := w.WriteByte(':'); err != nil {
				return err
			}
			if err := encodeCanonicalJSON(w, val[k]); err != nil {
				return err
			}
		}
		return w.WriteByte('}')
	default:
		return fmt.Errorf("configbundle: unsupported JSON type: %T", v)
	}
}
