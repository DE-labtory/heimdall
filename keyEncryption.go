package heimdall

import (
	"crypto/aes"
	"io"
	"crypto/rand"
	"crypto/cipher"
	"crypto/ecdsa"
)


// EncryptPriKey encrypts private key.
func EncryptPriKey(pri *ecdsa.PrivateKey, key []byte) (encryptedKey []byte, err error) {
	keyBytes := PriKeyToBytes(pri)

	encryptedKey, err = encryptWithAES(keyBytes, key)
	if err != nil {
		return nil, err
	}

	return encryptedKey, nil
}

// DecryptPriKey decrypts encrypted private key.
func DecryptPriKey(encryptedKey []byte, key []byte, curveOpt CurveOpts) (pri *ecdsa.PrivateKey, err error) {
	decKey, err := decryptWithAES(encryptedKey, key)
	if err != nil {
		return nil, err
	}

	pri, err = BytesToPriKey(decKey, curveOpt)
	if err != nil {
		return nil, err
	}

	return pri, nil
}

// EncryptWithAES encrypts plaintext with key by AES encryption algorithm.
func encryptWithAES(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize + len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// EncryptWithAES encrypts plaintext with key by AES encryption algorithm.
func decryptWithAES(ciphertext []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = make([]byte, len(ciphertext) - aes.BlockSize)
	iv := ciphertext[:aes.BlockSize]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return plaintext, nil
}