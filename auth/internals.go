// This file provides

package auth

import (
	"crypto"

	"github.com/it-chain/heimdall/key"
)

// SignerOpts contains options for signing with a Signer.
type SignerOpts interface {
	crypto.SignerOpts
}

// signer represents subject of signing process.
type signer interface {
	Sign(priKey key.Key, digest []byte, opts SignerOpts) ([]byte, error)
}

// verifier represents subject of verifying process.
type verifier interface {
	Verify(pubKey key.Key, signature, digest []byte, opts SignerOpts) (bool, error)
}
