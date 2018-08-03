// This file provides ECDSA signing and verifying related functions.

package heimdall

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"encoding/asn1"
	"errors"
	"crypto/x509"
)


// ecdsaSignature contains ECDSA signature components that are two big integers, R and S.
type ecdsaSignature struct {
	R, S *big.Int
}

// marshalECDSASignature returns encoding format (ASN.1) of signature.
func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{r, s})
}

// unmarshalECDSASignature parses the ASN.1 structure to ECDSA signature.
func unmarshalECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	ecdsaSig := new(ecdsaSignature)
	rest, err := asn1.Unmarshal(signature, ecdsaSig)
	if err != nil {
		return nil, nil, errors.New("failed to unmarshal")
	}

	if len(rest) != 0 {
		return nil, nil, errors.New("garbage following signature")
	}

	if ecdsaSig.R == nil {
		return nil, nil, errors.New("invalid signature")
	}

	if ecdsaSig.S == nil {
		return nil, nil, errors.New("invalid signature")
	}

	if ecdsaSig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature")
	}

	if ecdsaSig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature")
	}

	return ecdsaSig.R, ecdsaSig.S, nil
}

// Sign generates signature for a data using private key.
// if preBuf is not nil, data's hash append to preBuf - no malloc for hashed data.
func Sign(pri *ecdsa.PrivateKey, data, preBuf []byte, opts HashOpts) ([]byte, error) {
	digest, err := Hash(data, preBuf, opts)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, pri, digest)
	if err != nil {
		return nil, err
	}

	signature, err := marshalECDSASignature(r, s)
	if err != nil {
		return nil, err
	}

	// remove private key from memory.
	defer RemoveKeyMem(pri)

	return signature, nil
}

// Verify verifies the signature using pubKey(public key) and digest of original message, then returns boolean value.
func Verify(pub *ecdsa.PublicKey, signature, data, preBuf []byte, opts HashOpts) (bool, error) {
	digest, err := Hash(data, preBuf, opts)
	if err != nil {
		return false, err
	}

	r, s, err := unmarshalECDSASignature(signature)
	if err != nil {
		return false, err
	}

	valid := ecdsa.Verify(pub, digest, r, s)
	if !valid {
		return valid, nil
	}

	return valid, nil
}

// VerifyWithCert verify a signature with certificate.
func VerifyWithCert(cert *x509.Certificate, signature, data, preBuf []byte, opts HashOpts) (bool, error) {
	return Verify(cert.PublicKey.(*ecdsa.PublicKey), signature, data, preBuf, opts)
}