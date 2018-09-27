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

	"crypto/elliptic"

	"github.com/it-chain/heimdall/hecdsa"
	"github.com/stretchr/testify/assert"
)

func TestStringToKeyGenOpt(t *testing.T) {
	// given
	StrFmtOpt := "P-384"

	// when
	keyGenOpt := hecdsa.StringToKeyGenOpt(StrFmtOpt)

	// then
	assert.IsType(t, hecdsa.KeyGenOpts(1), keyGenOpt)
	assert.NotNil(t, keyGenOpt)
}

func TestCurveToKeyGenOpt(t *testing.T) {
	// given
	curve := elliptic.P384()

	// when
	keyGenOpt := hecdsa.CurveToKeyGenOpt(curve)

	// then
	assert.IsType(t, hecdsa.KeyGenOpts(1), keyGenOpt)
	assert.NotNil(t, keyGenOpt)
}

func TestKeyGenOpts_ToString(t *testing.T) {
	// given
	keyGenOpt := hecdsa.KeyGenOpts(hecdsa.ECP384)

	// when
	strFmtOpt := keyGenOpt.ToString()

	// then
	assert.IsType(t, string(""), strFmtOpt)
	assert.NotNil(t, strFmtOpt)
}

func TestKeyGenOpts_IsValid(t *testing.T) {
	// given
	validKeyGenOpt := hecdsa.KeyGenOpts(hecdsa.ECP384)
	invalidKeyGenOpt := hecdsa.KeyGenOpts(-1)
	invalidKeyGenOpt2 := hecdsa.StringToKeyGenOpt("P-999")

	// when
	valid := validKeyGenOpt.IsValid()
	invalid := invalidKeyGenOpt.IsValid()
	invalid2 := invalidKeyGenOpt2.IsValid()

	// then
	assert.True(t, valid)
	assert.False(t, invalid)
	assert.False(t, invalid2)
}

func TestKeyGenOpts_KeySize(t *testing.T) {
	// given
	keyGenOpt := hecdsa.KeyGenOpts(hecdsa.ECP384)

	// when
	keySize := keyGenOpt.KeySize()

	// then
	assert.NotEqual(t, -1, keySize)
}

func TestKeyGenOpts_ToCurve(t *testing.T) {
	// given
	keyGenOpt := hecdsa.KeyGenOpts(hecdsa.ECP384)

	// when
	curve := keyGenOpt.ToCurve()

	// then
	assert.Equal(t, elliptic.P384(), curve)
}
