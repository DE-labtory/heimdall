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

package config_test

import (
	"testing"

	"errors"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/config"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/stretchr/testify/assert"
)

func TestNewSimpleConfig(t *testing.T) {
	tests := map[string]struct {
		secLv     int
		keyGenOpt heimdall.KeyGenOpts
		hashOpt   hashing.HashOpts
		err       error
	}{
		"security level 128": {
			secLv:     128,
			keyGenOpt: hecdsa.KeyGenOpts(hecdsa.ECP256),
			hashOpt:   hashing.HashOpts(hashing.SHA256),
			err:       nil,
		},
		"security level 192": {
			secLv:     192,
			keyGenOpt: hecdsa.KeyGenOpts(hecdsa.ECP384),
			hashOpt:   hashing.HashOpts(hashing.SHA384),
			err:       nil,
		},
		"security level 256": {
			secLv:     256,
			keyGenOpt: hecdsa.KeyGenOpts(hecdsa.ECP521),
			hashOpt:   hashing.HashOpts(hashing.SHA512),
			err:       nil,
		},
		"invalid": {
			secLv:     111,
			keyGenOpt: nil,
			hashOpt:   hashing.HashOpts(0),
			err:       errors.New(config.ErrInvalidSecLv),
		},
	}

	for testName, test := range tests {
		t.Logf("running test case [%s]", testName)

		// given
		secLv := test.secLv

		// when
		conf, err := config.NewSimpleConfig(secLv)

		// then
		assert.Equal(t, test.keyGenOpt, conf.KeyGenOpt)
		assert.Equal(t, test.hashOpt, conf.HashOpt)
		assert.Equal(t, test.err, err)
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
