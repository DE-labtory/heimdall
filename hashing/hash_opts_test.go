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

package hashing_test

import (
	"testing"

	"crypto/sha512"
	"hash"

	"github.com/it-chain/heimdall/hashing"
	"github.com/stretchr/testify/assert"
)

func TestHashOpts_ToString(t *testing.T) {
	// given
	hashOpt := hashing.HashOpts(hashing.SHA384)

	// when
	strHash := hashOpt.ToString()

	// then
	assert.Equal(t, "SHA384", strHash)
}

func TestHashOpts_IsValid(t *testing.T) {
	// given
	validHashOpt := hashing.HashOpts(hashing.SHA384)
	invalidHashOpt := hashing.HashOpts(500)

	// when
	valid := validHashOpt.IsValid()
	invalid := invalidHashOpt.IsValid()

	// then
	assert.True(t, valid)
	assert.False(t, invalid)
}

func TestHashOpts_HashFunction(t *testing.T) {
	tests := map[string]struct {
		input  hashing.HashOpts
		output func() hash.Hash
	}{
		"SHA224 hash option": {
			input:  hashing.SHA224,
			output: sha512.New512_224,
		},
		"SHA256 hash option": {
			input:  hashing.SHA256,
			output: sha512.New512_256,
		},
		"SHA384 hash option": {
			input:  hashing.SHA384,
			output: sha512.New384,
		},
		"SHA512 hash option": {
			input:  hashing.SHA512,
			output: sha512.New,
		},
		"invalid hash option": {
			input:  hashing.HashOpts(500),
			output: nil,
		},
	}

	data := []byte("data")
	for testName, test := range tests {
		t.Logf("running test case [%s]", testName)
		// given
		hashOpt := hashing.HashOpts(test.input)

		// when
		hashFunc := hashOpt.HashFunction()

		// then
		if hashOpt.IsValid() {
			test.output().Write(data)
			hashFunc().Write(data)
			assert.Equal(t, test.output().Sum(nil), hashFunc().Sum(nil))
		} else {
			assert.Nil(t, test.output)
		}
	}
}

func TestStringToHashOpts(t *testing.T) {
	tests := map[string]struct {
		input  string
		output hashing.HashOpts
	}{
		"SHA224": {
			input:  "SHA224",
			output: hashing.SHA224,
		},
		"SHA256": {
			input:  "SHA256",
			output: hashing.SHA256,
		},
		"SHA384": {
			input:  "SHA384",
			output: hashing.SHA384,
		},
		"SHA512": {
			input:  "SHA512",
			output: hashing.SHA512,
		},
		"invalid": {
			input:  "SHA111",
			output: hashing.MaxHashOpt,
		},
	}

	for testName, test := range tests {
		t.Logf("running test case [%s]", testName)

		// given
		str := test.input

		// when
		hashOpt := hashing.StringToHashOpts(str)

		// then
		assert.Equal(t, test.output, hashOpt)
	}

}
