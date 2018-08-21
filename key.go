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

// This file provides ECDSA key related functions.

package heimdall

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/btcsuite/btcutil/base58"
	"encoding/hex"
	"strings"
)


// GenerateKey generates ECDSA key pair.
func GenerateKey(curveOpt CurveOpts) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curveOpt.CurveOptToCurve(), rand.Reader)
}

// PriKeyToBytes returns private key's D component as byte slice format.
func PriKeyToBytes(pri *ecdsa.PrivateKey) []byte {
	return pri.D.Bytes()
}

// BytesToPriKey converts key bytes (private key's D component) to private key format.
func BytesToPriKey(d []byte, curveOpt CurveOpts) (*ecdsa.PrivateKey, error) {
	pri := new(ecdsa.PrivateKey)
	pri.PublicKey.Curve = curveOpt.CurveOptToCurve()

	if 8 * len(d) != pri.Params().BitSize {
		return nil, errors.New("invalid private key - wrong length of key bytes for the entered curve option")
	}
	pri.D = new(big.Int).SetBytes(d)

	if pri.D.Cmp(pri.Params().N) >= 0 {
		return nil, errors.New("invalid private key - private key must be smaller than N of curve")
	}

	if pri.D.Sign() <= 0 {
		return nil, errors.New("invalid private key - private key should be positive value")
	}

	pri.PublicKey.X, pri.PublicKey.Y = pri.PublicKey.Curve.ScalarBaseMult(d)
	if pri.PublicKey.X == nil {
		return nil, errors.New("invalid private key - public key X component must not be nil")
	}

	return pri, nil
}

// PubKeyToBytes marshal and returns public key's X and Y coordinate as byte format.
func PubKeyToBytes(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

// BytesToPubKey converts key bytes (public key's X, Y coordinate) to public key format.
func BytesToPubKey(keyBytes []byte, curveOpt CurveOpts) (*ecdsa.PublicKey, error) {
	curve := curveOpt.CurveOptToCurve()
	x, y := elliptic.Unmarshal(curve, keyBytes)

	if x == nil {
		return new(ecdsa.PublicKey), errors.New("")
	}

	return &ecdsa.PublicKey{X: x, Y: y, Curve: curve}, nil
}

// SKIFromPubKey obtains Subject Key Identifier from public key.
func SKIFromPubKey(key *ecdsa.PublicKey) (ski []byte) {
	if key == nil {
		return nil
	}

	data := PubKeyToBytes(key)

	hash := sha256.New()
	hash.Write(data)

	return hash.Sum(nil)
}

// PubKeyToKeyID obtains key ID from public key.
func PubKeyToKeyID(key *ecdsa.PublicKey) string{
	return KeyIDPrefix + base58.Encode(SKIFromPubKey(key))
}

// SKIToKeyID obtains key ID from SKI(Subject Key Identifier).
func SKIToKeyID(ski []byte) string {
	return KeyIDPrefix + base58.Encode(ski)
}

// SKIFromKeyID obtains SKI from key ID.
func SKIFromKeyID(keyId string) []byte {
	return base58.Decode(strings.TrimPrefix(keyId, KeyIDPrefix))
}

// RemoveKeyMem initializes (remove existing values) private key's memory.
func RemoveKeyMem(pri *ecdsa.PrivateKey)  {
	pri.D = new(big.Int)
}

// SKIValidCheck checks if input SKI is corresponding to key id.
func SKIValidCheck(keyId string, ski string) error {
	skiBytes, err := hex.DecodeString(ski)
	if err != nil {
		return err
	}

	if SKIToKeyID(skiBytes) != keyId {
		return errors.New("invalid SKI - SKI is not correspond to key ID")
	}

	return nil
}

// KeyIDPrefixCheck checks if input key id has right prefix.
func KeyIDPrefixCheck(keyId string) error {
	if strings.HasPrefix(keyId, KeyIDPrefix) != true {
		return errors.New("invalid key ID - wrong prefix")
	}

	return nil
}