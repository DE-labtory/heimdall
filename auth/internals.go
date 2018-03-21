package auth

import (
	"crypto"
	"heimdall"
)

type SignerOpts interface {
	crypto.SignerOpts
}

type signer interface {

	Sign(key heimdall.Key, digest []byte, opts SignerOpts) ([]byte, error)

}

type verifier interface {

	Verify(key heimdall.Key, signature, digest []byte, opts SignerOpts) (bool, error)

}

type KeyGenOpts interface {

	Algorithm() string

}