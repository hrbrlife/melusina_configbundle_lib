# melusina_configbundle_lib

Shared canonical-JSON + Ed25519 + base58 primitive used by every Melusina
configurator wizard and the popaye-side `apply-ccash-config` consumer.

## Why this exists

Before this module was extracted, four wizards
(`melusina_partneroorg_app`, `melusina_vintageconfig_app`,
`melusina_cybertellerconfig_app`, `melusina_ccashconfig_app`) each shipped
a byte-identical copy of the canonical-JSON encoder + base58 codec +
Ed25519 sign/verify primitive. Three were 1:1 copies; the fourth differed
only in which root keys it stripped before signing. That left the whole
constellation one stray edit away from a silent canonical-form drift —
e.g. someone "improving" the encoder in one wizard would produce bundles
that no other verifier in the constellation could verify, but no test
would catch it.

This module is the single source of truth. The canonical bytes any
`Sign(...)` produces here are byte-identical to what every wizard
produced before the migration; the golden fixture in
`pkg/configbundle/golden_test.go` pins that contract.

## What it ships

```
pkg/configbundle/
├── canonical.go      # CanonicalizeBundleForSigning, MarshalCanonical
├── base58.go         # EncodeBase58 / DecodeBase58 (Bitcoin/Solana alphabet)
├── bundle.go         # BundleSignature, Sign, Verify, GenerateSigningKey, ParseSeed
├── errors.go         # ErrSchemaVersionMismatch, ErrUnsigned, ErrSignatureInvalid, ErrMissingRequired
├── canonical_test.go # pinned canonical-bytes regression
├── sign_verify_test.go
└── golden_test.go    # cross-impl golden fixture (DO NOT EDIT without propagating)
```

## How to use

### From a wizard repo

Add to your `go.mod`:

```
require github.com/hrbrlife/melusina_configbundle_lib v0.0.0

replace github.com/hrbrlife/melusina_configbundle_lib => ../melusina_configbundle_lib
```

Then in the wizard's signing code:

```go
import "github.com/hrbrlife/melusina_configbundle_lib/pkg/configbundle"

priv, err := configbundle.GenerateSigningKey()
if err != nil { return err }
bundle := bundleFromDoc(doc) // your wizard's typed Bundle
signed, sig, err := configbundle.Sign(bundle, priv, time.Now().UTC())
if err != nil { return err }
digest, err := configbundle.Verify(signed)
if err != nil { return err }
```

The wizard's `Bundle` struct should embed a `*configbundle.BundleSignature`
field tagged as `json:"bundle_signature,omitempty"` so serialised bundles
on disk carry the signature alongside the payload.

### From the ccashconfig family

The ccashconfig pattern strips two root keys (`signer_pubkey` and
`signature`) instead of the wizard family's single `bundle_signature`
nesting. Use the lower-level primitive directly:

```go
canonical, err := configbundle.CanonicalizeBundleForSigning(rawJSON, "signer_pubkey", "signature")
```

`pkg/configbundle.ErrSchemaVersionMismatch` is the shared sentinel for
schema-version drift detection (the ccashconfig wizard and
`apply-ccash-config` already use this; the wizards may adopt it as they
gain a `schema_version` field).

## Cross-impl golden fixture

`pkg/configbundle/golden_test.go` builds a canned bundle, runs it through
the canonical encoder, signs with a deterministic Ed25519 seed, and
asserts every byte against pinned constants:

- the canonical-bytes string (literal JSON)
- the canonical-bytes hex
- the canonical SHA-256 hex
- the signer's base58 pubkey
- the signature's base58

If any of those drift, the test fails with a self-describing error and
points to the constants you'd need to update in lockstep across every
downstream verifier. The fixture exists specifically to make
"someone tweaked the encoder in one wizard and it built fine" impossible.

## What it doesn't ship

- No higher-level `Bundle` Go type — each wizard owns its own typed
  bundle shape. The lib only supplies the primitive.
- No HTTP / Sandstorm bindings, no schema-version registry, no
  CLI scaffolding. Pure-Go, std-lib only, no transitive deps.

## Module identity

```
github.com/hrbrlife/melusina_configbundle_lib
```

Pure-Go, std-lib only, Go 1.25+.
