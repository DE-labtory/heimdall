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

func TestKeyStorer_StoreKey(t *testing.T) {
	// given
	keyDeriver := &kdf.ScryptKeyDeriver{}
	keyEncryptor := &encryption.AESCTREncryptor{}
	kdfOpt := kdf.NewScryptOpts(kdf.DefaultScryptN, kdf.DefaultScryptR, kdf.DefaultScryptP)
	encOpt := encryption.NewAESEncOpts(encryption.DefaultKeyLen, encryption.DefaultOpMode)

	keyStorer := keystore.NewKeyStorer(kdfOpt, encOpt, keyDeriver, keyEncryptor)
	assert.NotNil(t, keyStorer)

	pri, err := hecdsa.GenerateKey(hecdsa.ECP384)
	assert.NoError(t, err)

	// when
	err = keyStorer.StoreKey(pri, "password", heimdall.TestKeyDir)

	// then
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestKeyDir)
}

func TestKeyLoader_LoadKey(t *testing.T) {
	// given
	keyDeriver := &kdf.ScryptKeyDeriver{}
	keyEncryptor := &encryption.AESCTREncryptor{}
	kdfOpt := kdf.NewScryptOpts(kdf.DefaultScryptN, kdf.DefaultScryptR, kdf.DefaultScryptP)
	encOpt := encryption.NewAESEncOpts(encryption.DefaultKeyLen, encryption.DefaultOpMode)

	keyStorer := keystore.NewKeyStorer(kdfOpt, encOpt, keyDeriver, keyEncryptor)
	assert.NotNil(t, keyStorer)

	pri, err := hecdsa.GenerateKey(hecdsa.KeyGenOpts(hecdsa.ECP384))
	assert.NoError(t, err)

	err = keyStorer.StoreKey(pri, "password", heimdall.TestKeyDir)
	assert.NoError(t, err)

	keyRecoverer := &hecdsa.KeyRecoverer{}
	keyDecryptor := &encryption.AESCTRDecryptor{}
	keyDeriver = &kdf.ScryptKeyDeriver{}

	keyLoader := keystore.NewKeyLoader(keyDecryptor, keyRecoverer, keyDeriver)
	assert.NotNil(t, keyLoader)

	// when
	key, err := keyLoader.LoadKey(pri.ID(), "password", heimdall.TestKeyDir)

	// then
	assert.NoError(t, err)
	assert.Equal(t, pri.ID(), key.ID())
	assert.Equal(t, pri.KeyGenOpt(), key.KeyGenOpt())
	assert.Equal(t, pri.KeyType(), key.KeyType())

	defer os.RemoveAll(heimdall.TestKeyDir)
}
