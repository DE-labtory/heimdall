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
 *
 */

package heimdall_test

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/hex"
	"strings"
	"github.com/it-chain/heimdall"
)

func TestGenerateKey(t *testing.T) {
	pri, err := heimdall.GenerateKey(heimdall.TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, pri)
}

func TestPriKeyToBytes(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	keyBytes := heimdall.PriKeyToBytes(pri)
	assert.NotNil(t, keyBytes)
}

func TestBytesToPriKey(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	keyBytes := heimdall.PriKeyToBytes(pri)
	assert.NotNil(t, keyBytes)

	recPri, err := heimdall.BytesToPriKey(keyBytes, heimdall.TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, recPri)
	assert.EqualValues(t, pri, recPri)
}

func TestPubKeyToBytes(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	keyBytes := heimdall.PubKeyToBytes(&pri.PublicKey)
	assert.NotNil(t, keyBytes)
}

func TestBytesToPubKey(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	keyBytes := heimdall.PubKeyToBytes(&pri.PublicKey)
	assert.NotNil(t, keyBytes)

	pub, err := heimdall.BytesToPubKey(keyBytes, heimdall.TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, pub)
	assert.EqualValues(t, pub, &pri.PublicKey)
}

func TestSKIFromPubKey(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	ski := heimdall.SKIFromPubKey(&pri.PublicKey)
	assert.NotNil(t, ski)
}

func TestPubKeyToKeyID(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	keyId := heimdall.PubKeyToKeyID(&pri.PublicKey)
	assert.NotNil(t, keyId)
	assert.True(t, strings.HasPrefix(keyId, heimdall.KeyIDPrefix))
}

func TestSKIToKeyID(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	ski := heimdall.SKIFromPubKey(&pri.PublicKey)
	keyId := heimdall.SKIToKeyID(ski)
	assert.NotNil(t, keyId)
	assert.True(t, strings.HasPrefix(keyId, heimdall.KeyIDPrefix))
}

func TestSKIFromKeyID(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	keyId := heimdall.PubKeyToKeyID(&pri.PublicKey)
	ski := heimdall.SKIFromKeyID(keyId)
	assert.NotNil(t, ski)
}

func TestRemoveKeyMem(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	prevValue := pri.D
	heimdall.RemoveKeyMem(pri)
	assert.NotEqual(t, pri.D, prevValue)
	assert.Equal(t, pri.D.Int64(), int64(0))
}

func TestSKIValidCheck(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	ski := heimdall.SKIFromPubKey(&pri.PublicKey)
	keyId := heimdall.SKIToKeyID(ski)

	err := heimdall.SKIValidCheck(keyId, hex.EncodeToString(ski))
	assert.NoError(t, err)

	err = heimdall.SKIValidCheck(keyId, hex.EncodeToString([]byte("fake ski")))
	assert.Error(t, err)
}

func TestKeyIDPrefixCheck(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	ski := heimdall.SKIFromPubKey(&pri.PublicKey)
	keyId := heimdall.SKIToKeyID(ski)
	fakeKeyId := "fake" + keyId

	err := heimdall.KeyIDPrefixCheck(keyId)
	assert.NoError(t, err)

	err = heimdall.KeyIDPrefixCheck(fakeKeyId)
	assert.Error(t, err)
}