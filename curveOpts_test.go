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
	"crypto/elliptic"
	"github.com/it-chain/heimdall"
)


func TestCurveOpts_KeySize(t *testing.T) {
	keySize := heimdall.TestCurveOpt.KeySize()
	assert.NotNil(t, keySize)
}

func TestCurveOpts_ValidCheck(t *testing.T) {
	validBool := heimdall.TestCurveOpt.ValidCheck()
	assert.True(t, validBool)
}

func TestCurveOpts_String(t *testing.T) {
	curveOptStr := heimdall.TestCurveOpt.String()
	assert.NotNil(t, curveOptStr)
	assert.Equal(t, curveOptStr, "secp384r1")
}

func TestCurveOpts_CurveOptToCurve(t *testing.T) {
	curve := heimdall.TestCurveOpt.CurveOptToCurve()
	assert.NotNil(t, curve)
	assert.Equal(t, curve, elliptic.P384())
}

func TestStringToCurveOpt(t *testing.T) {
	curveOpt := heimdall.StringToCurveOpt("secp384r1")
	assert.NotEqual(t, curveOpt, heimdall.UNKNOWN)
	assert.Equal(t, curveOpt, heimdall.SECP384R1)
}

func TestCurveToCurveOpt(t *testing.T) {
	curve := elliptic.P384()
	curveOpt := heimdall.CurveToCurveOpt(curve)
	assert.NotEqual(t, curveOpt, heimdall.UNKNOWN)
	assert.Equal(t, curveOpt, heimdall.SECP384R1)
}