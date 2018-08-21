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
	"github.com/it-chain/heimdall"
	"github.com/stretchr/testify/assert"
)


func TestNewConfig(t *testing.T) {
	kdfParams := heimdall.DefaultScrpytParams
	conf, err := heimdall.NewConfig(192, heimdall.TestKeyDir, heimdall.TestCertDir, "AES-CTR", "ECDSA", "scrypt", kdfParams)
	assert.NoError(t, err)
	assert.NotNil(t, conf)

	assert.Equal(t, conf, heimdall.TestConf)
}

func TestNewDefaultConfig(t *testing.T) {
	conf := heimdall.NewDefaultConfig()
	assert.NotNil(t, conf)
}