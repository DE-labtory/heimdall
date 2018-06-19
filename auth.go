package heimdall

import (
	"crypto"
)

// SignerOpts contains options for signing with a Signer.
type SignerOpts interface {
	crypto.SignerOpts
}

// signer represents subject of signing process.
type Signer interface {
	Sign(priKey Key, digest []byte, opts SignerOpts) ([]byte, error)
}

// verifier represents subject of verifying process.
type Verifier interface {
	Verify(pubKey Key, signature, digest []byte, opts SignerOpts) (bool, error)
}