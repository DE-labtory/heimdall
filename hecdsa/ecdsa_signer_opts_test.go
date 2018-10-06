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

func TestSignerOpts_Algorithm(t *testing.T) {
	// given
	hashOpt, err := hashing.NewHashOpt(hashing.SHA384)
	assert.NoError(t, err)

	signerOpt := hecdsa.NewSignerOpts(hashOpt)

	// when
	algo := signerOpt.Algorithm()

	// then
	assert.Equal(t, "ECDSA", algo)
}

func TestSignerOpts_HashOpt(t *testing.T) {
	// given
	hashOpt, err := hashing.NewHashOpt(hashing.SHA384)
	assert.NoError(t, err)

	signerOpt := hecdsa.NewSignerOpts(hashOpt)

	// when
	hashOptFromSignerOpt := signerOpt.HashOpt()

	// then
	assert.Equal(t, hashOpt, hashOptFromSignerOpt)
}
