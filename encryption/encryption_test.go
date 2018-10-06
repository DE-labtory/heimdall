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

func TestEncryptKey(t *testing.T) {
	// given
	encKey := make([]byte, 24)
	_, err := rand.Read(encKey)
	assert.NoError(t, err)

	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	priKey, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	encOpt, err := encryption.NewOpts("AES", 128, "CTR")
	assert.NoError(t, err)

	// when
	encryptedPriKey, err := encryption.EncryptKey(priKey, encKey, encOpt)

	// then
	assert.NotNil(t, encryptedPriKey)
	assert.NoError(t, err)
}

func TestDecryptKey(t *testing.T) {
	// given
	encKey := make([]byte, 24)
	_, err := rand.Read(encKey)
	assert.NoError(t, err)

	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	priKey, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	encOpt, err := encryption.NewOpts("AES", 128, "CTR")
	assert.NoError(t, err)

	encryptedPriKey, err := encryption.EncryptKey(priKey, encKey, encOpt)
	assert.NotNil(t, encryptedPriKey)
	assert.NoError(t, err)

	keyBytes, err := priKey.ToByte()
	assert.NoError(t, err)

	// when
	decryptedKeyBytes, err := encryption.DecryptKey(encryptedPriKey, encKey, encOpt)

	// then
	assert.Equal(t, keyBytes, decryptedKeyBytes)
	assert.NoError(t, err)
}
