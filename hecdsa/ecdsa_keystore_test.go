/*
 * Copyright 2018 DE-labtory
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
	"testing"

	"os"

	"github.com/DE-labtory/heimdall"
	"github.com/DE-labtory/heimdall/encryption"
	"github.com/DE-labtory/heimdall/hecdsa"
	"github.com/DE-labtory/heimdall/kdf"
	"github.com/stretchr/testify/assert"
)

func TestStorePriKey(t *testing.T) {
	// given
	kdfOpt, err := kdf.NewOpts("SCRYPT", kdf.DefaultScryptParams)
	assert.NoError(t, err)
	encOpt, err := encryption.NewOpts("AES", encryption.DefaultKeyLen, encryption.DefaultOpMode)
	assert.NoError(t, err)

	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	// when
	err = hecdsa.StorePriKey(pri, "password", heimdall.TestPriKeyDir, encOpt, kdfOpt)

	// then
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestPriKeyDir)
}

func TestStorePubKey(t *testing.T) {
	// given
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	// when
	err = hecdsa.StorePubKey(pri.PublicKey(), heimdall.TestPubKeyDir)

	// then
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestPubKeyDir)
}

func TestStorePriKeyWithoutPwd(t *testing.T) {
	// given
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	// when
	err = hecdsa.StorePriKeyWithoutPwd(pri, heimdall.TestPriKeyDir)

	// then
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestPriKeyDir)
}

func TestLoadPriKey(t *testing.T) {
	// given
	kdfOpt, err := kdf.NewOpts(kdf.SCRYPT, kdf.DefaultScryptParams)
	assert.NoError(t, err)
	encOpt, err := encryption.NewOpts("AES", encryption.DefaultKeyLen, encryption.DefaultOpMode)
	assert.NoError(t, err)

	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	err = hecdsa.StorePriKey(pri, "password", heimdall.TestPriKeyDir, encOpt, kdfOpt)
	assert.NoError(t, err)

	// when
	key, err := hecdsa.LoadPriKey(heimdall.TestPriKeyDir, "password")

	// then
	assert.NoError(t, err)
	assert.Equal(t, pri.ID(), key.ID())
	assert.Equal(t, pri.KeyGenOpt(), key.KeyGenOpt())
	assert.Equal(t, pri.IsPrivate(), key.IsPrivate())

	defer os.RemoveAll(heimdall.TestPriKeyDir)
}

func TestLoadPubKey(t *testing.T) {
	// given
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	pub := pri.PublicKey()
	assert.NoError(t, err)

	err = hecdsa.StorePubKey(pub, heimdall.TestPubKeyDir)
	assert.NoError(t, err)

	// when
	key, err := hecdsa.LoadPubKey(pub.ID(), heimdall.TestPubKeyDir)

	// then
	assert.NoError(t, err)
	assert.Equal(t, pub.ID(), key.ID())
	assert.Equal(t, pub.KeyGenOpt(), key.KeyGenOpt())
	assert.Equal(t, pub.IsPrivate(), key.IsPrivate())

	defer os.RemoveAll(heimdall.TestPubKeyDir)
}

func TestLoadPriKeyWithoutPwd(t *testing.T) {
	// given
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	err = hecdsa.StorePriKeyWithoutPwd(pri, heimdall.TestPriKeyDir)
	assert.NoError(t, err)

	// when
	key, err := hecdsa.LoadPriKeyWithoutPwd(heimdall.TestPriKeyDir)

	// then
	assert.NoError(t, err)
	assert.Equal(t, pri.ID(), key.ID())
	assert.Equal(t, pri.KeyGenOpt(), key.KeyGenOpt())
	assert.Equal(t, pri.IsPrivate(), key.IsPrivate())

	defer os.RemoveAll(heimdall.TestPriKeyDir)
}
