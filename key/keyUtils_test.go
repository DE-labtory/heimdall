package key

import (
	"testing"

	"os"

	"encoding/pem"

	"github.com/stretchr/testify/assert"
	"encoding/hex"
	"github.com/it-chain/heimdall"
)

func TestPEMToPrivateKey(t *testing.T) {
	var keyGenOption = heimdall.KeyGenOpts(heimdall.RSA2048)

	testKeyManager, _ := NewKeyManager("./.testKeys")
	pri, _, _ := testKeyManager.GenerateKey(keyGenOption)

	priPEM, _ := pri.ToPEM()

	testPri, err := PEMToPrivateKey(priPEM, keyGenOption)
	assert.NotNil(t, testPri)
	assert.NoError(t, err)

	defer os.RemoveAll("./.testKeys")
}

func TestPEMToPublicKey(t *testing.T) {
	var keyGenOption = heimdall.KeyGenOpts(heimdall.RSA2048)

	testKeyManager, _ := NewKeyManager("./.testKeys")
	_, pub, _ := testKeyManager.GenerateKey(keyGenOption)

	pubPEM, _ := pub.ToPEM()

	testPub, err := PEMToPublicKey(pubPEM, keyGenOption)
	assert.NotNil(t, testPub)
	assert.NoError(t, err)

	defer os.RemoveAll("./.testKeys")
}

func TestDERToPrivateKey(t *testing.T) {
	var keyGenOption = heimdall.KeyGenOpts(heimdall.RSA2048)

	testKeyManager, _ := NewKeyManager("./.testKeys")
	pri, _, _ := testKeyManager.GenerateKey(keyGenOption)

	priPEM, _ := pri.ToPEM()
	block, _ := pem.Decode(priPEM)

	myPri, err := DERToPrivateKey(block.Bytes)
	assert.NotNil(t, myPri)
	assert.NoError(t, err)

	defer os.RemoveAll("./.testKeys")
}

func TestDERToPublicKey(t *testing.T) {
	var keyGenOption = heimdall.KeyGenOpts(heimdall.RSA2048)

	testKeyManager, _ := NewKeyManager("./.testKeys")
	_, pub, _ := testKeyManager.GenerateKey(keyGenOption)

	pubPEM, _ := pub.ToPEM()
	block, _ := pem.Decode(pubPEM)

	myPub, err := DERToPublicKey(block.Bytes)
	assert.NotNil(t, myPub)
	assert.NoError(t, err)

	defer os.RemoveAll("./.testKeys")
}

func TestMatchPrivateKeyOpt(t *testing.T) {
	var keyGenOption = heimdall.KeyGenOpts(heimdall.RSA2048)

	testKeyManager, _ := NewKeyManager("./.testKeys")
	pri, _, _ := testKeyManager.GenerateKey(keyGenOption)

	priPEM, _ := pri.ToPEM()

	block, _ := pem.Decode(priPEM)

	testPri, _ := DERToPrivateKey(block.Bytes)

	myPri, err := MatchPrivateKeyOpt(testPri, keyGenOption)
	assert.NoError(t, err)
	assert.NotNil(t, myPri)

	defer os.RemoveAll("./.testKeys")
}

func TestMatchPublicKeyOpt(t *testing.T) {
	var keyGenOption = heimdall.KeyGenOpts(heimdall.RSA2048)

	testKeyManager, _ := NewKeyManager("./.testKeys")
	_, pub, _ := testKeyManager.GenerateKey(keyGenOption)

	pubPEM, _ := pub.ToPEM()

	block, _ := pem.Decode(pubPEM)

	testPub, _ := DERToPublicKey(block.Bytes)

	myPub, err := MatchPublicKeyOpt(testPub, keyGenOption)
	assert.NoError(t, err)
	assert.NotNil(t, myPub)

	defer os.RemoveAll("./.testKeys")
}

func TestEncryptWithAES(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("plaintext for test")
	plaintext2 := []byte("plaintext for test")

	ciphertext, err := EncryptWithAES(plaintext, key)
	assert.NoError(t, err)
	assert.NotNil(t, ciphertext)

	ciphertext2, err := EncryptWithAES(plaintext2, key)
	assert.NotEqual(t, ciphertext, ciphertext2)
}

func TestDecryptWithAES(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("plaintext for test")

	ciphertext, _ := EncryptWithAES(plaintext, key)
	decPlaintext, err := DecryptWithAES(ciphertext, key)
	assert.NoError(t, err)
	assert.NotNil(t, decPlaintext)
}

func TestDeriveKeyFromPwd(t *testing.T) {
	pwd := []byte("password")
	salt := []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}
	pwd2 := []byte("password")

	targetLength := 32
	dKey, err := DeriveKeyFromPwd(pwd, salt, targetLength)
	assert.NotNil(t, dKey)
	assert.NoError(t, err)

	dKey2, _ := DeriveKeyFromPwd(pwd2, salt, targetLength)
	assert.Equal(t, dKey, dKey2)
}

func TestEncryptDecryptPriKey(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	var keyGenOption = heimdall.KeyGenOpts(heimdall.RSA2048)

	testKeyManager, _ := NewKeyManager("./.testKeys")
	pri, _, _ := testKeyManager.GenerateKey(keyGenOption)

	encKey, err := EncryptPriKey(pri, key)
	assert.NoError(t, err)
	assert.NotNil(t, encKey)

	decKey, err := DecryptPriKey(encKey, key, keyGenOption)
	assert.NoError(t, err)
	assert.NotNil(t, decKey)
	assert.Equal(t, pri, decKey)

	defer os.RemoveAll("./.testKeys")
}