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

package config_test

import (
	"testing"

	"github.com/DE-labtory/heimdall/config"
	"github.com/DE-labtory/heimdall/hashing"
	"github.com/DE-labtory/heimdall/hecdsa"
	"github.com/stretchr/testify/assert"
)

func TestNewSimpleConfig(t *testing.T) {
	tests := map[string]struct {
		secLv        int
		strKeyGenOpt string
		strHashOpt   string
		err          error
	}{
		"security level 128": {
			secLv:        128,
			strKeyGenOpt: hecdsa.ECP256,
			strHashOpt:   hashing.SHA256,
			err:          nil,
		},
		"security level 192": {
			secLv:        192,
			strKeyGenOpt: hecdsa.ECP384,
			strHashOpt:   hashing.SHA384,
			err:          nil,
		},
		"security level 256": {
			secLv:        256,
			strKeyGenOpt: hecdsa.ECP521,
			strHashOpt:   hashing.SHA512,
			err:          nil,
		},
		"invalid": {
			secLv:        111,
			strKeyGenOpt: "P-111",
			strHashOpt:   "SHA111",
			err:          config.ErrInvalidSecLv,
		},
	}

	for testName, test := range tests {
		t.Logf("running test case [%s]", testName)

		// given
		secLv := test.secLv

		// when
		conf, err := config.NewSimpleConfig(secLv)

		// then
		if err == nil {
			assert.Equal(t, test.strKeyGenOpt, conf.KeyGenOpt.ToString())
			assert.Equal(t, test.strHashOpt, conf.HashOpt.Name)
			assert.Equal(t, test.err, err)
		}
	}
}

func TestNewDefaultConfig(t *testing.T) {
	// when
	conf, err := config.NewDefaultConfig()

	// then
	assert.NoError(t, err)
	assert.NotNil(t, conf)
}

// todo: 기능 완성되면 작성
func TestNewDetailConfig(t *testing.T) {
}
