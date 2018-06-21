// This file provides key generator interface.

package key

import (
	"github.com/it-chain/heimdall"
	"crypto/rand"
	"crypto/rsa"
	"crypto/elliptic"
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// keyGenerator represents a key generator.
type keyGenerator interface {

	// Generate generates public and private key that match the input key generation option.
	Generate(opts heimdall.KeyGenOpts) (pri heimdall.PriKey, pub heimdall.PubKey, err error)
}

// An RSAKeyGenerator contains RSA key length.
type RSAKeyGenerator struct {
	bits int
}

// Generate returns private key and public key for RSA using key generation option.
func (keygen *RSAKeyGenerator) Generate(opts heimdall.KeyGenOpts) (pri heimdall.PriKey, pub heimdall.PubKey, err error) {

	if keygen.bits <= 0 {
		return nil, nil, errors.New("bits length should be bigger than 0")
	}

	generatedKey, err := rsa.GenerateKey(rand.Reader, keygen.bits)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key : %s", err)
	}

	pri = &RSAPrivateKey{PrivKey: generatedKey, Bits: keygen.bits}
	pub = pri.(*RSAPrivateKey).PublicKey()
	if err != nil {
		return nil, nil, err
	}

	return pri, pub, nil

}

// An ECDSAKeyGenerator contains elliptic curve for ECDSA.
type ECDSAKeyGenerator struct {
	curve elliptic.Curve
}

// Generate returns private key and public key for ECDSA using key generation option.
func (keygen *ECDSAKeyGenerator) Generate(opts heimdall.KeyGenOpts) (pri heimdall.PriKey, pub heimdall.PubKey, err error) {

	if keygen.curve == nil {
		return nil, nil, errors.New("curve value have not to be nil")
	}

	generatedKey, err := ecdsa.GenerateKey(keygen.curve, rand.Reader)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key : %s", err)
	}

	pri = &ECDSAPrivateKey{generatedKey}
	pub = pri.(*ECDSAPrivateKey).PublicKey()

	return pri, pub, nil

}