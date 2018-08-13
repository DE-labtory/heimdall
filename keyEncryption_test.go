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

package heimdall_test

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/it-chain/heimdall"
)

func TestEncryptPriKey(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	dKey, _ := heimdall.DeriveKeyFromPwd("scrypt", []byte("password"), heimdall.TestScrpytParams)

	encryptedKey, err := heimdall.EncryptPriKey(pri, dKey)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedKey)
}

func TestDecryptPriKey(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	dKey, _ := heimdall.DeriveKeyFromPwd("scrypt", []byte("password"), heimdall.TestScrpytParams)

	encryptedKey, _ := heimdall.EncryptPriKey(pri, dKey)

	decryptedKey, err := heimdall.DecryptPriKey(encryptedKey, dKey, heimdall.TestCurveOpt)
	assert.NotNil(t, decryptedKey)
	assert.NoError(t, err)
	assert.EqualValues(t, pri, decryptedKey)
}