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

package encryption_test

import (
	"testing"

	"github.com/DE-labtory/heimdall/encryption"
	"github.com/stretchr/testify/assert"
)

func TestNewOpts(t *testing.T) {
	tests := map[string]struct {
		algorithm string
		keyLen    int
		opMode    string
		err       error
	}{
		"valid": {
			algorithm: "AES",
			keyLen:    256,
			opMode:    "CTR",
			err:       nil,
		},
		"invalid algorithm": {
			algorithm: "TDES",
			keyLen:    256,
			opMode:    "CTR",
			err:       encryption.ErrAlgorithmNotSupported,
		},
		"invalid key length": {
			algorithm: "AES",
			keyLen:    112,
			opMode:    "CTR",
			err:       encryption.ErrKeyLengthNotSupported,
		},
		"invalid operation mode": {
			algorithm: "AES",
			keyLen:    256,
			opMode:    "ECB",
			err:       encryption.ErrOperationModeNotSupported,
		},
	}

	for testName, test := range tests {
		t.Logf("running test case [%s]", testName)

		// given
		algo := test.algorithm
		keyLen := test.keyLen
		opMode := test.opMode

		// when
		_, err := encryption.NewOpts(algo, keyLen, opMode)

		// then
		assert.Equal(t, test.err, err)
	}
}

func TestOpts_ToString(t *testing.T) {
	// given
	encAlgo := "AES"
	encKeyLen := 256
	encOpMode := "CTR"
	encOpt, err := encryption.NewOpts(encAlgo, encKeyLen, encOpMode)
	assert.NoError(t, err)

	// when
	strEncOpt := encOpt.ToString()

	// when
	assert.Equal(t, "AES_256_CTR", strEncOpt)
}
