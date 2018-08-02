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
	"strconv"
)

func TestDeriveKeyFromPwd(t *testing.T) {
	dKey, err := DeriveKeyFromPwd("scrypt", []byte("password"), TestScrpytParams)
	assert.NoError(t, err)
	assert.NotNil(t, dKey)
	keyLen, _ := strconv.Atoi(ScryptKeyLen)
	assert.Len(t, dKey, keyLen)

	dKey, err = DeriveKeyFromPwd("pbkdf2", []byte("password"), TestScrpytParams)
	assert.Error(t, err)
	assert.Nil(t, dKey)

	dKey, err = DeriveKeyFromPwd("mykdf", []byte("password"), TestScrpytParams)
	assert.Error(t, err)
	assert.Nil(t, dKey)
}
