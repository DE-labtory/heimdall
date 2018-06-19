// This file provides hash options.

package heimdall

// HashOpts represents hash options with integer.
type HashOpts int

const (
	SHA1 HashOpts = iota
	SHA224
	SHA256
	SHA384
	SHA512
)
