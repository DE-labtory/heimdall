package legacy

import (
	"crypto/rsa"
	"crypto"
)

type Key interface {

	SKI() (ski []byte)

	Algorithm() string

	ToPEM() ([]byte,error)

	Type() (keyType)

}

type Crypto interface {

	Sign(data []byte, opts SignerOpts) ([]byte, error)

	Verify(key Key, signature, digest []byte, opts SignerOpts) (bool, error)

	GetKey() (pri, pub Key, err error)
}

var DefaultRSAOption = &rsa.PSSOptions{SaltLength:rsa.PSSSaltLengthEqualsHash, Hash:crypto.SHA256}