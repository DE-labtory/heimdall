package heimdall

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"crypto/x509"
	"crypto/rand"
)

func TestSign(t *testing.T) {
	msg := []byte("message for test")
	pri, _ := GenerateKey(TestCurveOpt)

	signature, err := Sign(pri, msg, nil, TestHashOpt)
	assert.NoError(t, err)
	assert.NotNil(t, signature)

	assert.Equal(t, pri.D.Int64(), int64(0))
}

func TestVerify(t *testing.T) {
	msg := []byte("message for test")
	pri, _ := GenerateKey(TestCurveOpt)

	signature, _ := Sign(pri, msg, nil, TestHashOpt)

	valid, err := Verify(&pri.PublicKey, signature, msg, nil, TestHashOpt)
	assert.NoError(t, err)
	assert.True(t, valid)

	fakeMsg := append(msg, 1)
	valid, err = Verify(&pri.PublicKey, signature, fakeMsg, nil, TestHashOpt)
	assert.NoError(t, err)
	assert.False(t, valid)

	fakeSig, _ := Sign(pri, fakeMsg, nil, TestHashOpt)
	valid, err = Verify(&pri.PublicKey, fakeSig, msg, nil, TestHashOpt)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestVerifyWithCert(t *testing.T) {
	msg := []byte("message for test")
	pri, _ := GenerateKey(TestCurveOpt)

	signature, _ := Sign(pri, msg, nil, TestHashOpt)
	derBytes, _ := x509.CreateCertificate(rand.Reader, &testCertTemplate, &testCertTemplate, &pri.PublicKey, pri)
	cert, _ := x509.ParseCertificate(derBytes)

	valid, err := VerifyWithCert(cert, signature, msg, nil, TestHashOpt)
	assert.True(t, valid)
	assert.NoError(t, err)
}