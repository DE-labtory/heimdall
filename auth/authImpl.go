// This file provides implementation of the authentication interface.

package auth

import (
	"errors"
	"reflect"

	"github.com/it-chain/heimdall/key"
	"github.com/it-chain/heimdall"
)

// authImpl contains signers and verifiers that is used for signing and verifying process.
var signers map[reflect.Type]heimdall.Signer
var verifiers map[reflect.Type]heimdall.Verifier

//initialize signer and verifiers
func init() {

	signers = make(map[reflect.Type]heimdall.Signer)
	signers[reflect.TypeOf(&key.RSAPrivateKey{})] = &RSASigner{}
	signers[reflect.TypeOf(&key.ECDSAPrivateKey{})] = &ECDSASigner{}

	verifiers = make(map[reflect.Type]heimdall.Verifier)
	verifiers[reflect.TypeOf(&key.RSAPublicKey{})] = &RSAVerifier{}
	verifiers[reflect.TypeOf(&key.ECDSAPublicKey{})] = &ECDSAVerifier{}
}

// Sign signs a digest(hash) using priKey(private key), and returns signature.
func Sign(priKey heimdall.Key, digest []byte, opts heimdall.SignerOpts) ([]byte, error) {

	var err error

	if len(digest) == 0 {
		return nil, errors.New("invalid data")
	}

	if priKey == nil {
		return nil, errors.New("private key is not exist")
	}

	signer, found := signers[reflect.TypeOf(priKey)]
	if !found {
		return nil, errors.New("unsupported key type")
	}

	signature, err := signer.Sign(priKey, digest, opts)
	if err != nil {
		return nil, errors.New("signing error is occurred")
	}

	return signature, err

}

// Verify verifies the signature using pubKey(public key) and digest of original message, then returns boolean value.
func Verify(pubKey heimdall.Key, signature, digest []byte, opts heimdall.SignerOpts) (bool, error) {

	if pubKey == nil {
		return false, errors.New("invalid key")
	}

	if len(signature) == 0 {
		return false, errors.New("invalid signature")
	}

	if len(digest) == 0 {
		return false, errors.New("invalid digest")
	}

	verifier, found := verifiers[reflect.TypeOf(pubKey)]
	if !found {
		return false, errors.New("unsupported key type")
	}

	valid, err := verifier.Verify(pubKey, signature, digest, opts)
	if err != nil {
		return false, errors.New("verifying error is occurred")
	}

	return valid, nil

}
