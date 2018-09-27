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

package encryption_test

import (
	"testing"

	"github.com/it-chain/heimdall/encryption"
	"github.com/stretchr/testify/assert"
)

func TestNewAESEncOpts(t *testing.T) {
	// given
	encKeyLen := 256
	encOpMode := "CTR"

	// when
	encOpt := encryption.NewAESEncOpts(encKeyLen, encOpMode)

	// then
	assert.NotNil(t, encOpt)
}

func TestAESEncOpts_ToString(t *testing.T) {
	// given
	encKeyLen := 256
	encOpMode := "CTR"
	encOpt := encryption.NewAESEncOpts(encKeyLen, encOpMode)

	// when
	strEncOpt := encOpt.(*encryption.AESEncOpts).ToString()

	// when
	assert.Equal(t, "AES_256_CTR", strEncOpt)
}

func TestAESEncOpts_IsValid(t *testing.T) {
	// given
	encKeyLen := 256
	encOpMode := "CTR"
	invalidEncKeyLen := 111
	validEncOpt := encryption.NewAESEncOpts(encKeyLen, encOpMode)
	invalidEncOpt := encryption.NewAESEncOpts(invalidEncKeyLen, encOpMode)

	// when
	valid := validEncOpt.IsValid()
	invalid := invalidEncOpt.IsValid()

	// then
	assert.True(t, valid)
	assert.False(t, invalid)
}

func TestAESEncOpts_Algorithm(t *testing.T) {
	// given
	encKeyLen := 256
	encOpMode := "CTR"
	encOpt := encryption.NewAESEncOpts(encKeyLen, encOpMode)

	// when
	algo := encOpt.Algorithm()

	// then
	assert.Equal(t, encryption.AES, algo)
}

func TestAESEncOpts_KeyLen(t *testing.T) {
	// given
	encKeyLen := 256
	encOpMode := "CTR"
	encOpt := encryption.NewAESEncOpts(encKeyLen, encOpMode)

	// when
	keyLen := encOpt.KeyLen()

	// then
	assert.Equal(t, encKeyLen, keyLen)
}

func TestAESEncOpts_ToInnerFileInfo(t *testing.T) {
	// given
	encKeyLen := 256
	encOpMode := "CTR"
	encOpt := encryption.NewAESEncOpts(encKeyLen, encOpMode)

	// when
	fileEncInfo := encOpt.ToInnerFileInfo()

	// then
	assert.Equal(t, encryption.AES, fileEncInfo.Algo)
	assert.Equal(t, encKeyLen, fileEncInfo.KeyLen)
	assert.Equal(t, encOpMode, fileEncInfo.OpMode)
}

func TestStringToEncOpt(t *testing.T) {
	// given
	strEncOpt := "AES_256_CTR"
	invalidStrEncOpt := "ECDSA_256_CTR"
	invalidStrAESEncOpt := "AES_2&5_CTR"

	// when
	encOpt := encryption.StringToEncOpt(strEncOpt)
	invalidEncOpt := encryption.StringToEncOpt(invalidStrEncOpt)
	invalidEncOpt2 := encryption.StringToEncOpt(invalidStrAESEncOpt)

	// then
	assert.NotNil(t, encOpt)
	assert.Nil(t, invalidEncOpt)
	assert.Nil(t, invalidEncOpt2)
}
