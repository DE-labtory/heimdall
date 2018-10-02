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

	"strconv"

	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/kdf"
	"github.com/stretchr/testify/assert"
)

func TestNewScryptOpts(t *testing.T) {
	// when
	kdfOpt := kdf.NewScryptOpts(kdf.DefaultScryptN, kdf.DefaultScryptR, kdf.DefaultScryptP)

	// then
	assert.NotNil(t, kdfOpt)
}

// todo: 각 파라미터 제한치 찾아 기능 구현 후 작성
func TestScryptOpts_IsValid(t *testing.T) {
	// given
}

func TestScryptOpts_KDF(t *testing.T) {
	// given
	kdfOpt := kdf.NewScryptOpts(kdf.DefaultScryptN, kdf.DefaultScryptR, kdf.DefaultScryptP)

	// when
	strKDF := kdfOpt.KDF()

	// then
	assert.Equal(t, kdf.SCRYPT, strKDF)
}

func TestScryptOpts_ParamsToMap(t *testing.T) {
	// given
	kdfOpt := kdf.NewScryptOpts(kdf.DefaultScryptN, kdf.DefaultScryptR, kdf.DefaultScryptP)

	// when
	mapKdfOpt := kdfOpt.ParamsToMap()

	// then
	assert.Equal(t, strconv.Itoa(kdf.DefaultScryptN), mapKdfOpt["N"])
	assert.Equal(t, strconv.Itoa(kdf.DefaultScryptR), mapKdfOpt["R"])
	assert.Equal(t, strconv.Itoa(kdf.DefaultScryptP), mapKdfOpt["P"])
}

func TestScryptOpts_ToInnerFileInfo(t *testing.T) {
	// given
	kdfOpt := kdf.NewScryptOpts(kdf.DefaultScryptN, kdf.DefaultScryptR, kdf.DefaultScryptP)

	// when
	kdfInnerFileInfo := kdfOpt.ToInnerFileInfo()

	// then
	assert.Equal(t, kdf.SCRYPT, kdfInnerFileInfo.KDF)
	assert.Equal(t, kdfOpt.ParamsToMap(), kdfInnerFileInfo.Params)
}

func TestNewPbkdf2Opts(t *testing.T) {
	// when
	kdfOpt := kdf.NewPbkdf2Opts(kdf.DefaultPbkdf2Iteration, hashing.SHA384)

	// then
	assert.NotNil(t, kdfOpt)
}

// todo: 각 파라미터 제한치 찾아 기능 구현 후 작성
func TestPbkdf2Opts_IsValid(t *testing.T) {
	// given
}

func TestPbkdf2Opts_KDF(t *testing.T) {
	// given
	kdfOpt := kdf.NewPbkdf2Opts(kdf.DefaultPbkdf2Iteration, hashing.SHA384)

	// when
	strKDF := kdfOpt.KDF()

	// then
	assert.Equal(t, kdf.PBKDF2, strKDF)
}

func TestPbkdf2Opts_ParamsToMap(t *testing.T) {
	// given
	kdfOpt := kdf.NewPbkdf2Opts(kdf.DefaultPbkdf2Iteration, hashing.SHA384)

	// when
	mapKdfOpt := kdfOpt.ParamsToMap()

	// then
	assert.Equal(t, strconv.Itoa(kdf.DefaultPbkdf2Iteration), mapKdfOpt["iteration"])
	assert.Equal(t, strconv.Itoa(int(hashing.SHA384)), mapKdfOpt["hashOpt"])
}

func TestPbkdf2Opts_ToInnerFileInfo(t *testing.T) {
	// given
	kdfOpt := kdf.NewPbkdf2Opts(kdf.DefaultPbkdf2Iteration, hashing.SHA384)

	// when
	kdfInnerFileInfo := kdfOpt.ToInnerFileInfo()

	// then
	assert.Equal(t, kdf.PBKDF2, kdfInnerFileInfo.KDF)
	assert.Equal(t, kdfOpt.ParamsToMap(), kdfInnerFileInfo.Params)
}

func TestMapToOpts(t *testing.T) {
	// given
	scryptOpt := kdf.NewScryptOpts(kdf.DefaultScryptN, kdf.DefaultScryptR, kdf.DefaultScryptP)
	pbkdf2Opt := kdf.NewPbkdf2Opts(kdf.DefaultPbkdf2Iteration, hashing.SHA384)

	scryptFileInfo := scryptOpt.ToInnerFileInfo()
	pbkdf2FileInfo := pbkdf2Opt.ToInnerFileInfo()

	// when
	recoveredScryptOpt := kdf.MapToOpts(scryptFileInfo)
	recoveredPbkdf2Opt := kdf.MapToOpts(pbkdf2FileInfo)

	// then
	assert.Equal(t, scryptOpt, recoveredScryptOpt)
	assert.Equal(t, pbkdf2Opt, recoveredPbkdf2Opt)
}
