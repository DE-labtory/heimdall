package heimdall

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"os"
)

func TestNewKeyStore(t *testing.T) {
	ks, err := NewKeyStore(TestKeyDir)
	assert.NoError(t, err)
	assert.NotNil(t, ks)
	assert.NotEmpty(t, ks.path)
}

func TestKeystore_StoreKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)

	ks, _ := NewKeyStore(TestKeyDir)
	err := ks.StoreKey(pri, "password")
	assert.NoError(t, err)

	defer os.RemoveAll(TestKeyDir)
}

func TestKeystore_LoadKey(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)

	ks, _ := NewKeyStore(TestKeyDir)
	_ = ks.StoreKey(pri, "password")

	keyId := PubKeyToKeyID(&pri.PublicKey)
	loadedPri, err := ks.LoadKey(keyId, "password")
	assert.NoError(t, err)
	assert.NotNil(t, loadedPri)
	assert.EqualValues(t, loadedPri, pri)

	defer os.RemoveAll(TestKeyDir)
}
