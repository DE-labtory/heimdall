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

package hecdsa

import (
	"testing"

	"math/big"

	"github.com/stretchr/testify/assert"
)

func TestPriKey_Clear(t *testing.T) {
	// given
	keyGenOpt, err := NewKeyGenOpt(ECP384)
	assert.NoError(t, err)
	pri, err := GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	// when
	pri.Clear()

	// then
	assert.Equal(t, big.NewInt(0).Bytes(), pri.(*PriKey).internalPriKey.D.Bytes())
}
