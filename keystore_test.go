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
	"os"
	"github.com/it-chain/heimdall"
)

func TestNewKeyStore(t *testing.T) {
	ks, err := heimdall.NewKeyStore(heimdall.TestConf.KeyDirPath, heimdall.TestConf.Kdf, heimdall.TestConf.KdfParams, heimdall.TestConf.EncAlgo, heimdall.TestConf.EncKeyLength)
	assert.NoError(t, err)
	assert.NotNil(t, ks)
}

func TestKeystore_StoreKey(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)

	ks, _ := heimdall.NewKeyStore(heimdall.TestConf.KeyDirPath, heimdall.TestConf.Kdf, heimdall.TestConf.KdfParams, heimdall.TestConf.EncAlgo, heimdall.TestConf.EncKeyLength)
	err := ks.StoreKey(pri, "password")
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestKeyDir)
}

func TestKeystore_LoadKey(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestConf.CurveOpt)

	ks, _ := heimdall.NewKeyStore(heimdall.TestConf.KeyDirPath, heimdall.TestConf.Kdf, heimdall.TestConf.KdfParams, heimdall.TestConf.EncAlgo, heimdall.TestConf.EncKeyLength)
	_ = ks.StoreKey(pri, "password")

	keyId := heimdall.PubKeyToKeyID(&pri.PublicKey)
	loadedPri, err := ks.LoadKey(keyId, "password")
	assert.NoError(t, err)
	assert.NotNil(t, loadedPri)
	assert.EqualValues(t, loadedPri, pri)

	defer os.RemoveAll(heimdall.TestKeyDir)
}
