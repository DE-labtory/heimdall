package heimdall

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"crypto/elliptic"
)


func TestCurveOpts_KeySize(t *testing.T) {
	keySize := TestCurveOpt.KeySize()
	assert.NotNil(t, keySize)
}

func TestCurveOpts_ValidCheck(t *testing.T) {
	validBool := TestCurveOpt.ValidCheck()
	assert.True(t, validBool)
}

func TestCurveOpts_String(t *testing.T) {
	curveOptStr := TestCurveOpt.String()
	assert.NotNil(t, curveOptStr)
	assert.Equal(t, curveOptStr, "secp384r1")
}

func TestCurveOpts_CurveOptToCurve(t *testing.T) {
	curve := TestCurveOpt.CurveOptToCurve()
	assert.NotNil(t, curve)
	assert.Equal(t, curve, elliptic.P384())
}

func TestStringToCurveOpt(t *testing.T) {
	curveOpt := StringToCurveOpt("secp384r1")
	assert.NotEqual(t, curveOpt, UNKNOWN)
	assert.Equal(t, curveOpt, SECP384R1)
}

func TestCurveToCurveOpt(t *testing.T) {
	curve := elliptic.P384()
	curveOpt := CurveToCurveOpt(curve)
	assert.NotEqual(t, curveOpt, UNKNOWN)
	assert.Equal(t, curveOpt, SECP384R1)
}