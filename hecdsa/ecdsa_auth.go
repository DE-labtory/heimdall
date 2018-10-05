/*
 * Copyright 2018 It-chain
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// This file provides ECDSA signing and verifying related functions.

package hecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"

	"crypto/x509"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/keystore"
)

var ErrInvalidSignature = [...]error{
	errors.New("invalid signature - garbage follows signature"),
	errors.New("invalid signature - signature's R value should not be nil"),
	errors.New("invalid signature - signature's S value should not be nil"),
	errors.New("invalid signature - signature's R value should be positive except zero"),
	errors.New("invalid signature - signature's S value should be positive except zero"),
}

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
		return nil, nil, err
	}

	if len(rest) != 0 {
		return nil, nil, ErrInvalidSignature[0]
	}

	if ecdsaSig.R == nil {
		return nil, nil, ErrInvalidSignature[1]
	}

	if ecdsaSig.S == nil {
		return nil, nil, ErrInvalidSignature[2]
	}

	if ecdsaSig.R.Sign() != 1 {
		return nil, nil, ErrInvalidSignature[3]
	}

	if ecdsaSig.S.Sign() != 1 {
		return nil, nil, ErrInvalidSignature[4]
	}

	return ecdsaSig.R, ecdsaSig.S, nil
}

func SignWithKeyInLocal(keyID heimdall.KeyID, keyDirPath, pwd string, message []byte, hashOpt hashing.HashOpts) ([]byte, error) {
	recoverer := &KeyRecoverer{}
	signerOpt := NewSignerOpts(hashOpt)
	pri, err := keystore.LoadKey(keyID, pwd, keyDirPath, recoverer)
	if err != nil {
		return nil, err
	}

	return Sign(pri.(*PriKey), message, signerOpt)
}

// Sign generates signature for a data using private key.
func Sign(pri heimdall.PriKey, message []byte, opts heimdall.SignerOpts) ([]byte, error) {
	digest, err := hashing.Hash(message, opts.HashOpt())
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, pri.(*PriKey).internalPriKey, digest)
	if err != nil {
		return nil, err
	}

	signature, err := marshalECDSASignature(r, s)
	if err != nil {
		return nil, err
	}

	// remove private key from memory.
	defer pri.Clear()

	return signature, nil
}

// Verify verifies the signature using pubKey(public key) and digest of original message, then returns boolean value.
func Verify(pub heimdall.PubKey, signature, message []byte, opts heimdall.SignerOpts) (bool, error) {
	digest, err := hashing.Hash(message, opts.HashOpt())
	if err != nil {
		return false, err
	}

	r, s, err := unmarshalECDSASignature(signature)
	if err != nil {
		return false, err
	}

	valid := ecdsa.Verify(pub.(*PubKey).internalPubKey, digest, r, s)
	return valid, nil
}

// VerifyWithCert verify a signature with certificate.
func VerifyWithCert(cert *x509.Certificate, signature, message []byte, opts heimdall.SignerOpts) (bool, error) {
	pub := NewPubKey(cert.PublicKey.(*ecdsa.PublicKey))
	return Verify(pub, signature, message, opts)
}
