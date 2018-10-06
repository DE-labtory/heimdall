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

package kdf_test

import (
	"testing"

	"github.com/it-chain/heimdall/kdf"
	"github.com/stretchr/testify/assert"
)

func TestNewOpt(t *testing.T) {
	// given
	kdfName := "SCRYPT"
	kdfParams := kdf.DefaultScryptParams

	// when
	kdfOpt, err := kdf.NewOpts(kdfName, kdfParams)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, kdfOpt)
	assert.Equal(t, kdf.DefaultScryptN, kdfOpt.KdfParams["N"])
	assert.Equal(t, kdf.DefaultScryptR, kdfOpt.KdfParams["R"])
	assert.Equal(t, kdf.DefaultScryptP, kdfOpt.KdfParams["P"])
}
