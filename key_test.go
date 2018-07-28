package heimdall

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestGenerateKey(t *testing.T) {
	pri, err := GenerateKey(TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, pri)
}

func TestPriKeyToBytes(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyBytes := PriKeyToBytes(pri)
	assert.NotNil(t, keyBytes)
}

func TestBytesToPriKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyBytes := PriKeyToBytes(pri)
	assert.NotNil(t, keyBytes)

	recPri, err := BytesToPriKey(keyBytes, TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, recPri)
	assert.EqualValues(t, pri, recPri)
}

func TestPubKeyToBytes(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyBytes := PubKeyToBytes(&pri.PublicKey)
	assert.NotNil(t, keyBytes)
}

func TestBytesToPubKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyBytes := PubKeyToBytes(&pri.PublicKey)
	assert.NotNil(t, keyBytes)

	pub, err := BytesToPubKey(keyBytes, TestCurveOpt)
	assert.NoError(t, err)
	assert.NotNil(t, pub)
	assert.EqualValues(t, pub, &pri.PublicKey)
}

func TestSKIFromPubKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	ski := SKIFromPubKey(&pri.PublicKey)
	assert.NotNil(t, ski)
}

func TestPubKeyToKeyID(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyId := PubKeyToKeyID(&pri.PublicKey)
	assert.NotNil(t, keyId)
}

func TestSKIToKeyID(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	ski := SKIFromPubKey(&pri.PublicKey)
	keyId := SKIToKeyID(ski)
	assert.NotNil(t, keyId)
}

func TestSKIFromKeyID(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	keyId := PubKeyToKeyID(&pri.PublicKey)
	ski := SKIFromKeyID(keyId)
	assert.NotNil(t, ski)
}

func TestRemoveKeyMem(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	prevValue := pri.D
	RemoveKeyMem(pri)
	assert.NotEqual(t, pri.D, prevValue)
	assert.Equal(t, pri.D.Int64(), int64(0))
}