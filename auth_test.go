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
)

func TestSign(t *testing.T) {
	msg := []byte("message for test")
	pri, _ := GenerateKey(TestCurveOpt)
	digest, _ := Hash(msg, nil, SHA512)

	signature, err := Sign(pri, digest)
	assert.NoError(t, err)
	assert.NotNil(t, signature)

	assert.Equal(t, pri.D.Int64(), int64(0))
}

func TestVerify(t *testing.T) {
	msg := []byte("message for test")
	pri, _ := GenerateKey(TestCurveOpt)
	digest, _ := Hash(msg, nil, SHA512)

	signature, _ := Sign(pri, digest)

	valid, err := Verify(&pri.PublicKey, signature, digest)
	assert.NoError(t, err)
	assert.True(t, valid)

	otherdigest, _ := Hash([]byte("fake msg"), nil, SHA512)
	valid, err = Verify(&pri.PublicKey, signature, otherdigest)
	assert.Error(t, err)
	assert.False(t, valid)
}