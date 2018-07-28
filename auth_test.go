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