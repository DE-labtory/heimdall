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

package hecdsa_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/stretchr/testify/assert"
)

func setUpPriKey(t *testing.T) *hecdsa.PriKey {
	generator := hecdsa.KeyGenerator{}

	pri, err := generator.GenerateKey(hecdsa.ECP384)
	assert.NoError(t, err)

	return pri.(*hecdsa.PriKey)
}

func TestECDSAKeyGenerator_GenerateKey(t *testing.T) {
	// given
	generator := hecdsa.KeyGenerator{}

	// when
	pri, err := generator.GenerateKey(hecdsa.ECP384)
	wrongPri, err2 := generator.GenerateKey(hecdsa.KeyGenOpts(100))

	// then
	assert.NoError(t, err)
	assert.NotNil(t, pri)

	assert.Error(t, err2)
	assert.Nil(t, wrongPri)
}

func TestNewPriKey(t *testing.T) {
	// given
	ecdsaPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	// when
	pri := hecdsa.NewPriKey(ecdsaPri)

	// then
	assert.NotNil(t, pri)
}

func TestPriKey_ID(t *testing.T) {
	// given
	pri := setUpPriKey(t)
	otherPri := setUpPriKey(t)

	// when
	keyId := pri.ID()
	otherKeyId := otherPri.ID()

	// then
	assert.NoError(t, heimdall.KeyIDPrefixCheck(keyId))
	assert.NoError(t, heimdall.KeyIDPrefixCheck(otherKeyId))
	assert.NotEqual(t, otherKeyId, keyId)
}

func TestPriKey_SKI(t *testing.T) {
	// given
	pri := setUpPriKey(t)
	otherPri := setUpPriKey(t)

	// when
	ski := pri.SKI()
	otherSki := otherPri.SKI()

	// then
	assert.NotEqual(t, otherSki, ski)
}

func TestPriKey_ToByte(t *testing.T) {
	// given
	pri := setUpPriKey(t)

	// when
	priBytes := pri.ToByte()

	// then
	assert.NotNil(t, priBytes)
}

func TestPriKey_KeyGenOpt(t *testing.T) {
	// given
	pri := setUpPriKey(t)

	// when
	keyGenOpt := pri.KeyGenOpt()

	// then
	assert.Equal(t, hecdsa.ECP384, keyGenOpt)
}

func TestPriKey_KeyType(t *testing.T) {
	// given
	pri := setUpPriKey(t)

	// when
	keyType := pri.KeyType()

	// then
	assert.Equal(t, heimdall.KeyType(heimdall.PRIVATEKEY), keyType)
}

func TestPriKey_PublicKey(t *testing.T) {
	// given
	pri := setUpPriKey(t)

	// when
	pub := pri.PublicKey()

	// then
	assert.NotNil(t, pub)
}

func TestNewPubKey(t *testing.T) {
	// given
	ecdsaPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	ecdsaPub := &ecdsaPri.PublicKey

	// when
	pub := hecdsa.NewPubKey(ecdsaPub)

	// then
	assert.NotNil(t, pub)
}

func TestPubKey_ID(t *testing.T) {
	// given
	pub := setUpPriKey(t).PublicKey()
	otherPub := setUpPriKey(t).PublicKey()

	// when
	keyId := pub.ID()
	otherKeyId := otherPub.ID()

	// then
	assert.NoError(t, heimdall.KeyIDPrefixCheck(keyId))
	assert.NoError(t, heimdall.KeyIDPrefixCheck(otherKeyId))
	assert.NotEqual(t, otherKeyId, keyId)
}

func TestPubKey_SKI(t *testing.T) {
	// given
	pub := setUpPriKey(t).PublicKey()
	otherPub := setUpPriKey(t).PublicKey()

	// when
	ski := pub.SKI()
	otherSki := otherPub.SKI()

	// then
	assert.NotEqual(t, otherSki, ski)
}

func TestPubKey_ToByte(t *testing.T) {
	// given
	pub := setUpPriKey(t).PublicKey()

	// when
	pubBytes := pub.ToByte()

	// then
	assert.NotNil(t, pubBytes)
}

func TestPubKey_KeyGenOpt(t *testing.T) {
	// given
	pub := setUpPriKey(t).PublicKey()

	// when
	keyGenOpt := pub.KeyGenOpt()

	// then
	assert.Equal(t, hecdsa.ECP384, keyGenOpt)
}

func TestPubKey_KeyType(t *testing.T) {
	// given
	pub := setUpPriKey(t).PublicKey()

	// when
	keyType := pub.KeyType()

	// then
	assert.Equal(t, heimdall.KeyType(heimdall.PUBLICKEY), keyType)
}

func TestKeyRecoverer_RecoverKeyFromByte(t *testing.T) {
	// given
	pri := setUpPriKey(t)
	pub := pri.PublicKey()

	priBytes := pri.ToByte()
	pubBytes := pub.ToByte()

	keyRecoverer := hecdsa.KeyRecoverer{}

	// when
	priKey, err := keyRecoverer.RecoverKeyFromByte(priBytes, pri.KeyType(), pri.KeyGenOpt().ToString())
	pubKey, err2 := keyRecoverer.RecoverKeyFromByte(pubBytes, pub.KeyType(), pub.KeyGenOpt().ToString())

	// then
	assert.NoError(t, err)
	assert.NoError(t, err2)
	assert.Equal(t, pri, priKey)
	assert.Equal(t, pub, pubKey)
}
