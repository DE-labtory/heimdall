/*
 * Copyright 2018 DE-labtory
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

// This file provides functions for encryption and decryption functions for private key.

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"errors"

	"github.com/DE-labtory/heimdall"
)

func EncryptKey(pri heimdall.Key, key []byte, opts *Opts) (encryptedKey []byte, err error) {
	switch opts.Algorithm {
	case AES:
		switch opts.OpMode {
		case CTR:
			return encryptKeyWithAESCTR(pri, key)
		default:
			return nil, ErrOperationModeNotSupported
		}
	default:
		return nil, ErrAlgorithmNotSupported
	}

	return nil, errors.New("fatal error during EncryptKey()")
}

// AESCTREncryptKey encrypts private key.
func encryptKeyWithAESCTR(pri heimdall.Key, key []byte) (encryptedKey []byte, err error) {
	keyBytes, err := pri.ToByte()
	if err != nil {
		return nil, err
	}

	encryptedKey, err = encryptWithAESCTR(keyBytes, key)
	if err != nil {
		return nil, err
	}

	return encryptedKey, nil
}

// encryptWithAESCTR encrypts plaintext with key by AES algorithm.
func encryptWithAESCTR(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func DecryptKey(encryptedKey, key []byte, opts *Opts) ([]byte, error) {
	switch opts.Algorithm {
	case AES:
		switch opts.OpMode {
		case CTR:
			return decryptKeyWithAESCTR(encryptedKey, key)
		default:
			return nil, ErrOperationModeNotSupported
		}
	default:
		return nil, ErrAlgorithmNotSupported
	}

	return nil, errors.New("fatal error during DecryptKey()")
}

// AESCTRDecryptKey decrypts encrypted private key.
func decryptKeyWithAESCTR(encryptedKey []byte, key []byte) ([]byte, error) {
	decKey, err := decryptWithAESCTR(encryptedKey, key)
	if err != nil {
		return nil, err
	}

	return decKey, nil
}

// decryptWithAESCTR decrypts ciphertext with key by AES algorithm.
func decryptWithAESCTR(ciphertext []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = make([]byte, len(ciphertext)-aes.BlockSize)
	iv := ciphertext[:aes.BlockSize]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return plaintext, nil
}
