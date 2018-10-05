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
	"testing"

	"crypto/rand"

	"github.com/it-chain/heimdall/kdf"
	"github.com/stretchr/testify/assert"
)

func TestDeriveKey(t *testing.T) {
	tests := map[string]struct {
		kdfName   string
		kdfParams map[string]int
		err       error
	}{
		"scrypt option": {
			kdfName:   "SCRYPT",
			kdfParams: kdf.DefaultScryptParams,
			err:       nil,
		},
		"pbkdf2 option": {
			kdfName:   "PBKDF2",
			kdfParams: kdf.DefaultPbkdf2Params,
			err:       nil,
		},
		"not supported option": {
			kdfName:   "BCRYPT",
			kdfParams: kdf.DefaultScryptParams,
			err:       kdf.ErrKdfNotSupported,
		},
	}

	pwd := []byte("password")
	keyLen := 128

	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	assert.NoError(t, err)

	for testCase, test := range tests {
		t.Logf("running test case [%s]", testCase)

		// given
		kdfOpt, _ := kdf.NewOpts(test.kdfName, test.kdfParams)

		// when
		_, err := kdf.DeriveKey(pwd, salt, keyLen, kdfOpt)

		// then
		assert.Equal(t, test.err, err)
	}

}
