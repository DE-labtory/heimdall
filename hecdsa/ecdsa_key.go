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

	"crypto/elliptic"
	"crypto/rand"

	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
	"github.com/it-chain/heimdall"
)

var ErrECDSAKeyGenOpt = errors.New("invalid ECDSA key generating option")
var ErrKeyBytesLength = errors.New("invalid key bytes length - wrong length of key bytes for the entered curve option")
var ErrPriKeySize = errors.New("invalid private key - private key must be smaller than N of curve")
var ErrPriKeyValue = errors.New("invalid private key - private key should not be zero or negative")
var ErrPubKeyValue = errors.New("invalid public key - public key X component must not be nil")
var ErrKeyType = errors.New("invalid key type - key type should be heimdall.PRIVATEKEY or heimdall.PUBLICKEY")

// KeyGenerator is an implementation of KeyGenerator interface to generate ECDSA key
type KeyGenerator struct {
}

func (generator *KeyGenerator) GenerateKey(keyGenOpt heimdall.KeyGenOpts) (heimdall.PriKey, error) {
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

func (priKey *PriKey) ToByte() []byte {
	return priKey.internalPriKey.D.Bytes()
}

func (priKey *PriKey) KeyGenOpt() heimdall.KeyGenOpts {
	pubKey := PubKey{&priKey.internalPriKey.PublicKey}
	return StringToKeyGenOpt(pubKey.internalPubKey.Curve.Params().Name)
}

func (priKey *PriKey) KeyType() heimdall.KeyType {
	return heimdall.PRIVATEKEY
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
	return heimdall.KeyID(heimdall.KeyIDPrefix + base58.Encode(pubKey.SKI()))
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

func (pubKey *PubKey) ToByte() []byte {
	return elliptic.Marshal(pubKey.internalPubKey.Curve, pubKey.internalPubKey.X, pubKey.internalPubKey.Y)
}

func (pubKey *PubKey) KeyGenOpt() heimdall.KeyGenOpts {
	return StringToKeyGenOpt(pubKey.internalPubKey.Curve.Params().Name)
}

func (pubKey *PubKey) KeyType() heimdall.KeyType {
	return heimdall.PUBLICKEY
}

type KeyRecoverer struct {
}

func (recoverer *KeyRecoverer) RecoverKeyFromByte(keyBytes []byte, keyType heimdall.KeyType, strFmtKeyGenOpt string) (heimdall.Key, error) {
	curve := StringToKeyGenOpt(strFmtKeyGenOpt).ToCurve()

	switch keyType {
	case heimdall.PRIVATEKEY:
		pri := new(PriKey)
		pri.internalPriKey = new(ecdsa.PrivateKey)

		pri.internalPriKey.PublicKey.Curve = curve

		if 8*len(keyBytes) != pri.internalPriKey.Params().BitSize {
			return nil, ErrKeyBytesLength
		}
		pri.internalPriKey.D = new(big.Int).SetBytes(keyBytes)

		if pri.internalPriKey.D.Cmp(pri.internalPriKey.Params().N) >= 0 {
			return nil, ErrPriKeySize
		}

		if pri.internalPriKey.D.Sign() <= 0 {
			return nil, ErrPriKeyValue
		}

		pri.internalPriKey.PublicKey.X, pri.internalPriKey.PublicKey.Y = pri.internalPriKey.PublicKey.Curve.ScalarBaseMult(keyBytes)
		if pri.internalPriKey.PublicKey.X == nil {
			return nil, ErrPubKeyValue
		}

		return pri, nil

	case heimdall.PUBLICKEY:
		x, y := elliptic.Unmarshal(curve, keyBytes)

		if x == nil {
			return nil, ErrPubKeyValue
		}

		pub := new(PubKey)
		pub.internalPubKey = new(ecdsa.PublicKey)
		pub.internalPubKey.X = x
		pub.internalPubKey.Y = y
		pub.internalPubKey.Curve = curve

		return pub, nil
	}

	return nil, ErrKeyType
}
