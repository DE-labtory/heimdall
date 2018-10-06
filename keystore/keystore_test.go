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

package keystore_test

import (
	"testing"

	"os"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/encryption"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/it-chain/heimdall/kdf"
	"github.com/it-chain/heimdall/keystore"
	"github.com/stretchr/testify/assert"
)

func TestStoreKey(t *testing.T) {
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
	err = keystore.StoreKey(pri, "password", heimdall.TestKeyDir, encOpt, kdfOpt)

	// then
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestKeyDir)
}

func TestLoadKey(t *testing.T) {
	// given
	kdfOpt, err := kdf.NewOpts(kdf.SCRYPT, kdf.DefaultScryptParams)
	assert.NoError(t, err)
	encOpt, err := encryption.NewOpts("AES", encryption.DefaultKeyLen, encryption.DefaultOpMode)
	assert.NoError(t, err)

	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	err = keystore.StoreKey(pri, "password", heimdall.TestKeyDir, encOpt, kdfOpt)
	assert.NoError(t, err)

	keyRecoverer := &hecdsa.KeyRecoverer{}

	// when
	key, err := keystore.LoadKey(pri.ID(), "password", heimdall.TestKeyDir, keyRecoverer)

	// then
	assert.NoError(t, err)
	assert.Equal(t, pri.ID(), key.ID())
	assert.Equal(t, pri.KeyGenOpt(), key.KeyGenOpt())
	assert.Equal(t, pri.IsPrivate(), key.IsPrivate())

	defer os.RemoveAll(heimdall.TestKeyDir)
}
