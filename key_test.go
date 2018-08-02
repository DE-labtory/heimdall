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

package heimdall

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/hex"
	"strings"
)

func TestGenerateKey(t *testing.T) {
	pri, err := GenerateKey(TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, pri)
}

func TestPriKeyToBytes(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyBytes := PriKeyToBytes(pri)
	assert.NotNil(t, keyBytes)
}

func TestBytesToPriKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyBytes := PriKeyToBytes(pri)
	assert.NotNil(t, keyBytes)

	recPri, err := BytesToPriKey(keyBytes, TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, recPri)
	assert.EqualValues(t, pri, recPri)
}

func TestPubKeyToBytes(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyBytes := PubKeyToBytes(&pri.PublicKey)
	assert.NotNil(t, keyBytes)
}

func TestBytesToPubKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyBytes := PubKeyToBytes(&pri.PublicKey)
	assert.NotNil(t, keyBytes)

	pub, err := BytesToPubKey(keyBytes, TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, pub)
	assert.EqualValues(t, pub, &pri.PublicKey)
}

func TestSKIFromPubKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	ski := SKIFromPubKey(&pri.PublicKey)
	assert.NotNil(t, ski)
}

func TestPubKeyToKeyID(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyId := PubKeyToKeyID(&pri.PublicKey)
	assert.NotNil(t, keyId)
	assert.True(t, strings.HasPrefix(keyId, keyIDPrefix))
}

func TestSKIToKeyID(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	ski := SKIFromPubKey(&pri.PublicKey)
	keyId := SKIToKeyID(ski)
	assert.NotNil(t, keyId)
	assert.True(t, strings.HasPrefix(keyId, keyIDPrefix))
}

func TestSKIFromKeyID(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyId := PubKeyToKeyID(&pri.PublicKey)
	ski := SKIFromKeyID(keyId)
	assert.NotNil(t, ski)
}

func TestRemoveKeyMem(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	prevValue := pri.D
	RemoveKeyMem(pri)
	assert.NotEqual(t, pri.D, prevValue)
	assert.Equal(t, pri.D.Int64(), int64(0))
}

func TestSKIValidCheck(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	ski := SKIFromPubKey(&pri.PublicKey)
	keyId := SKIToKeyID(ski)

	err := SKIValidCheck(keyId, hex.EncodeToString(ski))
	assert.NoError(t, err)

	err = SKIValidCheck(keyId, hex.EncodeToString([]byte("fake ski")))
	assert.Error(t, err)
}

func TestKeyIDPrefixCheck(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	ski := SKIFromPubKey(&pri.PublicKey)
	keyId := SKIToKeyID(ski)
	fakeKeyId := "fake" + keyId

	err := KeyIDPrefixCheck(keyId)
	assert.NoError(t, err)

	err = KeyIDPrefixCheck(fakeKeyId)
	assert.Error(t, err)
}