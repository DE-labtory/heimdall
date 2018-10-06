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

package hecdsa_test

import (
	"testing"

	"github.com/it-chain/heimdall/hecdsa"
	"github.com/stretchr/testify/assert"
)

func TestNewKeyGenOpt(t *testing.T) {
	// given
	inputStrFmtOpt := "P-384"

	// when
	keyGenOpt, err := hecdsa.NewKeyGenOpt(inputStrFmtOpt)

	// then
	assert.Equal(t, inputStrFmtOpt, keyGenOpt.ToString())
	assert.NoError(t, err)
}

func TestKeyGenOpt_ToString(t *testing.T) {
	// given
	inputStrFmtOpt := "P-384"
	keyGenOpt, err := hecdsa.NewKeyGenOpt(inputStrFmtOpt)
	assert.NoError(t, err)

	// when
	strFmtOpt := keyGenOpt.ToString()

	// then
	assert.Equal(t, inputStrFmtOpt, strFmtOpt)
}

func TestKeyGenOpt_KeySize(t *testing.T) {
	// given
	inputStrFmtOpt := "P-384"
	keyGenOpt, err := hecdsa.NewKeyGenOpt(inputStrFmtOpt)
	assert.NoError(t, err)

	// when
	keySize := keyGenOpt.KeySize()

	// then
	assert.Equal(t, 384, keySize)
}
