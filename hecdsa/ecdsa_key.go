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
 */

package hecdsa

import (
	"crypto/ecdsa"

	"crypto/rand"

	"crypto/sha256"
	"errors"
	"math/big"

	"crypto/x509"

	"github.com/btcsuite/btcutil/base58"
	"github.com/it-chain/heimdall"
)

var ErrECDSAKeyGenOpt = errors.New("invalid ECDSA key generating option")
var ErrKeyType = errors.New("invalid key type - key type should be heimdall.PRIVATEKEY or heimdall.PUBLICKEY")

func GenerateKey(keyGenOpt heimdall.KeyGenOpts) (heimdall.PriKey, error) {
	valid := keyGenOpt.IsValid()
	if !valid {
		return nil, ErrECDSAKeyGenOpt
	}

	pri, err := ecdsa.GenerateKey(keyGenOpt.(KeyGenOpts).ToCurve(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &PriKey{pri}, nil
}

// PriKey is an implementation of heimdall PriKey for using ECDSA private key
type PriKey struct {
	internalPriKey *ecdsa.PrivateKey
}

func NewPriKey(internalPriKey *ecdsa.PrivateKey) heimdall.PriKey {
	return &PriKey{internalPriKey: internalPriKey}
}

func (priKey *PriKey) ID() heimdall.KeyID {
	pubKey := PubKey{&priKey.internalPriKey.PublicKey}
	return pubKey.ID()
}

func (priKey *PriKey) SKI() []byte {
	pubKey := PubKey{&priKey.internalPriKey.PublicKey}
	return pubKey.SKI()
}

func (priKey *PriKey) ToByte() ([]byte, error) {
	return x509.MarshalECPrivateKey(priKey.internalPriKey)
}

func (priKey *PriKey) KeyGenOpt() heimdall.KeyGenOpts {
	pubKey := PubKey{&priKey.internalPriKey.PublicKey}
	return StringToKeyGenOpt(pubKey.internalPubKey.Curve.Params().Name)
}

func (priKey *PriKey) IsPrivate() bool {
	return true
}

func (priKey *PriKey) PublicKey() heimdall.PubKey {
	return &PubKey{&priKey.internalPriKey.PublicKey}
}

func (priKey *PriKey) Clear() {
	// clear private key's D value to 0
	priKey.internalPriKey.D.Set(big.NewInt(0))
}

// PubKey is an implementation of heimdall PubKey for using ECDSA public key
type PubKey struct {
	internalPubKey *ecdsa.PublicKey
}

func NewPubKey(internalPubKey *ecdsa.PublicKey) heimdall.PubKey {
	return &PubKey{internalPubKey: internalPubKey}
}

func (pubKey *PubKey) ID() heimdall.KeyID {
	// return base58 encoded ski with key id prefix
	return heimdall.KeyIDPrefix + base58.Encode(pubKey.SKI())
}

func (pubKey *PubKey) SKI() []byte {
	// get keyBytes from key
	keyBytes := pubKey.ToByte()

	// get ski from keyBytes
	hash := sha256.New()
	hash.Write(keyBytes)
	ski := hash.Sum(nil)

	return ski
}

func (pubKey *PubKey) ToByte() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pubKey.internalPubKey)
}

func (pubKey *PubKey) KeyGenOpt() heimdall.KeyGenOpts {
	return StringToKeyGenOpt(pubKey.internalPubKey.Curve.Params().Name)
}

func (pubKey *PubKey) IsPrivate() bool {
	return false
}

type KeyRecoverer struct {
}

func (recoverer *KeyRecoverer) RecoverKeyFromByte(keyBytes []byte, isPrivate bool) (heimdall.Key, error) {
	switch isPrivate {
	case true:
		internalPriKey, err := x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}

		pri := NewPriKey(internalPriKey)

		return pri, nil

	case false:
		internalPubKey, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}

		pub := NewPubKey(internalPubKey.(*ecdsa.PublicKey))

		return pub, nil

	default:
		return nil, ErrKeyType
	}
}
