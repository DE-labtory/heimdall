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

package kdf_test

import (
	"crypto/rand"
	"testing"

	"github.com/it-chain/heimdall/encryption"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/kdf"
	"github.com/stretchr/testify/assert"
)

func TestScryptKeyDeriver_DeriveKey(t *testing.T) {
	// given
	keyDeriver := kdf.ScryptKeyDeriver{}
	scryptOpt := kdf.NewScryptOpts(kdf.DefaultScryptN, kdf.DefaultScryptR, kdf.DefaultScryptP)

	pwdBytes := []byte("password")
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	assert.NoError(t, err)

	// when
	derivedKey, err := keyDeriver.DeriveKey(pwdBytes, salt, encryption.DefaultKeyLen, scryptOpt)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, derivedKey)
	assert.Len(t, derivedKey, encryption.DefaultKeyLen/8) // bit to byte
}

func TestPbkdf2KeyDeriver_DeriveKey(t *testing.T) {
	// given
	keyDeriver := kdf.Pbkdf2KeyDeriver{}
	pbkdf2Opt := kdf.NewPbkdf2Opts(kdf.DefaultPbkdf2Iteration, hashing.SHA384)

	pwdBytes := []byte("password")
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	assert.NoError(t, err)

	// when
	derivedKey, err := keyDeriver.DeriveKey(pwdBytes, salt, encryption.DefaultKeyLen, pbkdf2Opt)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, derivedKey)
	assert.Len(t, derivedKey, encryption.DefaultKeyLen/8) // bit to byte
}
