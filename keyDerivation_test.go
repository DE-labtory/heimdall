package heimdall

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"strconv"
)

func TestDeriveKeyFromPwd(t *testing.T) {
	dKey, err := DeriveKeyFromPwd("scrypt", []byte("password"), TestScrpytParams)
	assert.NoError(t, err)
	assert.NotNil(t, dKey)
	keyLen, _ := strconv.Atoi(ScryptKeyLen)
	assert.Len(t, dKey, keyLen)

	dKey, err = DeriveKeyFromPwd("pbkdf2", []byte("password"), TestScrpytParams)
	assert.Error(t, err)
	assert.Nil(t, dKey)

	dKey, err = DeriveKeyFromPwd("mykdf", []byte("password"), TestScrpytParams)
	assert.Error(t, err)
	assert.Nil(t, dKey)
}
