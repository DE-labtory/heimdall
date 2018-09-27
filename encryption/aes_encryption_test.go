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

package encryption_test

import (
	"testing"

	"crypto/rand"

	"github.com/it-chain/heimdall/encryption"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/stretchr/testify/assert"
)

func TestAESCTREncryptor_EncryptKey(t *testing.T) {
	// given
	encKey := make([]byte, 24)
	_, err := rand.Read(encKey)
	assert.NoError(t, err)

	generator := hecdsa.KeyGenerator{}
	priKey, err := generator.GenerateKey(hecdsa.ECP384)
	assert.NoError(t, err)

	encryptor := encryption.AESCTREncryptor{}

	// when
	encryptedPriKey, err := encryptor.EncryptKey(priKey, encKey)

	// then
	assert.NotNil(t, encryptedPriKey)
	assert.NoError(t, err)
}

func TestAESCTRDecryptor_DecryptKey(t *testing.T) {
	// given
	encKey := make([]byte, 24)
	_, err := rand.Read(encKey)
	assert.NoError(t, err)

	generator := hecdsa.KeyGenerator{}
	priKey, err := generator.GenerateKey(hecdsa.ECP384)
	assert.NoError(t, err)

	encryptor := encryption.AESCTREncryptor{}
	decryptor := encryption.AESCTRDecryptor{}

	encryptedPriKey, err := encryptor.EncryptKey(priKey, encKey)
	assert.NotNil(t, encryptedPriKey)
	assert.NoError(t, err)

	// when
	keyBytes, err := decryptor.DecryptKey(encryptedPriKey, encKey)

	// then
	assert.Equal(t, priKey.ToByte(), keyBytes)
	assert.NoError(t, err)
}
