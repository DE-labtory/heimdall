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
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	return pri.(*hecdsa.PriKey)
}

func TestGenerateKey(t *testing.T) {
	// given
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)

	// when
	pri, err := hecdsa.GenerateKey(keyGenOpt)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, pri)
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
	assert.Equal(t, 20, len(ski))
}

func TestPriKey_ToByte(t *testing.T) {
	// given
	pri := setUpPriKey(t)

	// when
	priBytes, err := pri.ToByte()

	// then
	assert.NoError(t, err)
	assert.NotNil(t, priBytes)
}

func TestPriKey_KeyGenOpt(t *testing.T) {
	// given
	pri := setUpPriKey(t)

	// when
	keyGenOpt := pri.KeyGenOpt()

	// then
	assert.Equal(t, hecdsa.ECP384, keyGenOpt.ToString())
}

func TestPriKey_IsPrivate(t *testing.T) {
	// given
	pri := setUpPriKey(t)

	// when
	isPrivate := pri.IsPrivate()

	// then
	assert.True(t, isPrivate)
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
	assert.Equal(t, 20, len(ski))
}

func TestPubKey_ToByte(t *testing.T) {
	// given
	pub := setUpPriKey(t).PublicKey()

	// when
	pubBytes, err := pub.ToByte()

	// then
	assert.NotNil(t, pubBytes)
	assert.NoError(t, err)
}

func TestPubKey_KeyGenOpt(t *testing.T) {
	// given
	pub := setUpPriKey(t).PublicKey()

	// when
	keyGenOpt := pub.KeyGenOpt()

	// then
	assert.Equal(t, hecdsa.ECP384, keyGenOpt.ToString())
}

func TestPubKey_IsPrivate(t *testing.T) {
	// given
	pub := setUpPriKey(t).PublicKey()

	// when
	isPrivate := pub.IsPrivate()

	// then
	assert.False(t, isPrivate)
}

func TestKeyRecoverer_RecoverKeyFromByte(t *testing.T) {
	// given
	pri := setUpPriKey(t)
	pub := pri.PublicKey()

	priBytes, err := pri.ToByte()
	assert.NoError(t, err)
	pubBytes, err := pub.ToByte()
	assert.NoError(t, err)

	keyRecoverer := hecdsa.KeyRecoverer{}

	// when
	priKey, err := keyRecoverer.RecoverKeyFromByte(priBytes, pri.IsPrivate())
	pubKey, err2 := keyRecoverer.RecoverKeyFromByte(pubBytes, pub.IsPrivate())

	// then
	assert.NoError(t, err)
	assert.NoError(t, err2)
	assert.Equal(t, pri, priKey)
	assert.Equal(t, pub, pubKey)
}
