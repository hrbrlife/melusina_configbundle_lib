package configbundle

import "errors"

// ErrSchemaVersionMismatch is returned by callers when a loaded
// bundle's SchemaVersion does not match what they were built for.
// Lifted into the shared lib (it originated in ccashconfig) so that
// every consumer can `errors.Is(err, configbundle.ErrSchemaVersionMismatch)`
// without depending on a specific wizard's package.
var ErrSchemaVersionMismatch = errors.New("configbundle: schema version mismatch")

// ErrMissingRequired is returned by Validate-style checks when a
// required field is empty. Originated in ccashconfig.
var ErrMissingRequired = errors.New("configbundle: missing required field")

// ErrUnsigned is returned when a Verify call is given a bundle that
// has no embedded signature block.
var ErrUnsigned = errors.New("configbundle: bundle is unsigned")

// ErrSignatureInvalid is returned when Ed25519 verification fails
// against the recomputed canonical bytes.
var ErrSignatureInvalid = errors.New("configbundle: bundle signature is invalid")
