package auth

import (
	"crypto"
	"heimdall"
	"github.com/it-chain/heimdall/key"
)

type SignerOpts interface {
	crypto.SignerOpts
}

type signer interface {

	Sign(key key.Key, digest []byte, opts SignerOpts) ([]byte, error)

}

type verifier interface {

	Verify(key key.Key, signature, digest []byte, opts SignerOpts) (bool, error)

}