package heimdall

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestEncryptPriKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	dKey, _ := DeriveKeyFromPwd("scrypt", []byte("password"), TestScrpytParams)

	encryptedKey, err := EncryptPriKey(pri, dKey)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedKey)
}

func TestDecryptPriKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	dKey, _ := DeriveKeyFromPwd("scrypt", []byte("password"), TestScrpytParams)

	encryptedKey, _ := EncryptPriKey(pri, dKey)

	decryptedKey, err := DecryptPriKey(encryptedKey, dKey, TestCurveOpt)
	assert.NotNil(t, decryptedKey)
	assert.NoError(t, err)
	assert.EqualValues(t, pri, decryptedKey)
}