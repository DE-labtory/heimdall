/*
 * Copyright 2018 DE-labtory
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
	"strings"
	"testing"

	"github.com/DE-labtory/heimdall"
	"github.com/DE-labtory/heimdall/hecdsa"
	"github.com/stretchr/testify/assert"
)

func TestSKIToKeyID(t *testing.T) {
	// given
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	ski := pri.SKI()

	// when
	keyId := heimdall.SKIToKeyID(ski)

	// then
	assert.NotNil(t, keyId)
	assert.True(t, strings.HasPrefix(keyId, heimdall.KeyIDPrefix))
}

func TestSKIValidCheck(t *testing.T) {
	// given
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	ski := pri.SKI()

	keyId := heimdall.SKIToKeyID(ski)

	// when
	err = heimdall.SKIValidCheck(keyId, ski)
	err2 := heimdall.SKIValidCheck(keyId, []byte("fake ski"))

	// then
	assert.NoError(t, err)
	assert.Error(t, err2)
}

func TestKeyIDPrefixCheck(t *testing.T) {
	// given
	keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(keyGenOpt)
	assert.NoError(t, err)

	ski := pri.SKI()

	keyId := heimdall.SKIToKeyID(ski)
	fakeKeyId := "fake" + keyId

	// when
	err = heimdall.KeyIDPrefixCheck(keyId)
	err2 := heimdall.KeyIDPrefixCheck(fakeKeyId)

	// then
	assert.NoError(t, err)
	assert.Error(t, err2)
}
