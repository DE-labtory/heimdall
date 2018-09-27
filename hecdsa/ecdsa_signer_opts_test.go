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

	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/stretchr/testify/assert"
)

func TestSignerOpts_IsValid(t *testing.T) {
	// given
	validSignerOpt := hecdsa.SignerOpts("SHA384")
	invalidSignerOpt := hecdsa.SignerOpts("invalid option")

	// when
	valid := validSignerOpt.IsValid()
	invalid := invalidSignerOpt.IsValid()

	// then
	assert.True(t, valid)
	assert.False(t, invalid)
}

func TestSignerOpts_HashOpt(t *testing.T) {
	// given
	signerOpt := hecdsa.SignerOpts("SHA384")

	// when
	hashOpt := signerOpt.HashOpt()

	// then
	assert.IsType(t, hashing.HashOpts(2), hashOpt)
	assert.Equal(t, "SHA384", hashOpt.ToString())
}
