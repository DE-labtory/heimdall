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
	"github.com/it-chain/heimdall"
)

func TestSign(t *testing.T) {
	msg := []byte("message for test")
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)

	signature, err := heimdall.Sign(pri, msg, nil, heimdall.TestHashOpt)
	assert.NoError(t, err)
	assert.NotNil(t, signature)

	assert.Equal(t, pri.D.Int64(), int64(0))
}

func TestVerify(t *testing.T) {
	msg := []byte("message for test")
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)

	signature, _ := heimdall.Sign(pri, msg, nil, heimdall.TestHashOpt)

	valid, err := heimdall.Verify(&pri.PublicKey, signature, msg, nil, heimdall.TestHashOpt)
	assert.NoError(t, err)
	assert.True(t, valid)

	fakeMsg := append(msg, 1)
	valid, err = heimdall.Verify(&pri.PublicKey, signature, fakeMsg, nil, heimdall.TestHashOpt)
	assert.NoError(t, err)
	assert.False(t, valid)

	fakeSig, _ := heimdall.Sign(pri, fakeMsg, nil, heimdall.TestHashOpt)
	valid, err = heimdall.Verify(&pri.PublicKey, fakeSig, msg, nil, heimdall.TestHashOpt)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestVerifyWithCert(t *testing.T) {
	msg := []byte("message for test")
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)

	signature, _ := heimdall.Sign(pri, msg, nil, heimdall.TestHashOpt)
	cert, _ := heimdall.PemToX509Cert([]byte(heimdall.TestCertPemBytes))

	valid, err := heimdall.VerifyWithCert(cert, signature, msg, nil, heimdall.TestHashOpt)
	assert.True(t, valid)
	assert.NoError(t, err)
}