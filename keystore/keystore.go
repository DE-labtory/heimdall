/*
 * Copyright 2018 It-chain
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

// This file provides functions for storing and loading ECDSA key pair.

package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/kdf"
)

var ErrInvalidKeyGenOpt = errors.New("invalid ECDSA key generation option - not supported curve")
var ErrInvalidKDFOpt = errors.New("invalid key derivation option")
var ErrWrongKeyID = errors.New("wrong key id - failed to find key using key ID")
var ErrEmptyKeyPath = errors.New("invalid keyPath - keyPath empty")

// struct for encrypted key's file format.
type KeyFile struct {
	SKI          []byte
	KeyGenOpt    string
	KeyType      int
	EncryptedKey string
	Hints        EncryptionHints
}

// struct for providing hints of encryption and key derivation function.
type EncryptionHints struct {
	EncInnerFileInfo heimdall.EncInnerFileInfo
	KDFInnerFileInfo heimdall.KDFInnerFileInfo
	KDFSalt          []byte
}

type KeyStorer struct {
	kdfOpt heimdall.KeyDerivationOpts
	encOpt heimdall.EncryptOpts
	heimdall.KeyDeriver
	heimdall.KeyEncryptor
}

func NewKeyStorer(kdfOpt heimdall.KeyDerivationOpts, encOpt heimdall.EncryptOpts, keyDeriver heimdall.KeyDeriver, keyEncryptor heimdall.KeyEncryptor) heimdall.KeyStorer {
	return &KeyStorer{
		kdfOpt:       kdfOpt,
		encOpt:       encOpt,
		KeyDeriver:   keyDeriver,
		KeyEncryptor: keyEncryptor,
	}
}

// StoreKey stores private key that is encrypted by key derived from input password.
func (keyStorer *KeyStorer) StoreKey(key heimdall.Key, pwd string, keyDirPath string) error {
	ski := key.SKI()
	keyId := key.ID()

	keyGenOpt := key.KeyGenOpt()
	if !keyGenOpt.IsValid() {
		return ErrInvalidKeyGenOpt
	}

	keyFilePath, err := keyStorer.makeKeyFilePath(keyId, keyDirPath)
	if err != nil {
		return err
	}

	salt := make([]byte, 8)
	_, err = rand.Read(salt)
	if err != nil {
		return err
	}

	dKey, err := keyStorer.DeriveKey([]byte(pwd), salt, keyStorer.encOpt.KeyLen(), keyStorer.kdfOpt)
	if err != nil {
		return err
	}

	encryptedKeyBytes, err := keyStorer.EncryptKey(key, dKey)
	if err != nil {
		return err
	}

	jsonKeyFile, err := keyStorer.makeJsonKeyFile(salt, ski, keyGenOpt, encryptedKeyBytes, key.KeyType())
	if err != nil {
		return err
	}

	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		err = ioutil.WriteFile(keyFilePath, jsonKeyFile, 0700)
		if err != nil {
			return err
		}
	}

	return nil
}

// makeKeyFilePath makes key file path (absolute) of the key file.
func (keyStorer *KeyStorer) makeKeyFilePath(keyFileName string, keyDirPath string) (string, error) {
	if _, err := os.Stat(keyDirPath); os.IsNotExist(err) {
		err = os.MkdirAll(keyDirPath, 0755)
		if err != nil {
			return "", err
		}
	}

	return filepath.Join(keyDirPath, keyFileName), nil
}

// makeJsonKeyFile marshals keyFile struct to json format.
func (keyStorer *KeyStorer) makeJsonKeyFile(kdfSalt []byte, ski []byte, keyGenOpt heimdall.KeyGenOpts, encryptedKeyBytes []byte, keyType heimdall.KeyType) ([]byte, error) {
	encHints := EncryptionHints{
		EncInnerFileInfo: keyStorer.encOpt.ToInnerFileInfo(),
		KDFInnerFileInfo: keyStorer.kdfOpt.ToInnerFileInfo(),
		KDFSalt:          kdfSalt,
	}

	keyFile := KeyFile{
		SKI:          ski,
		KeyGenOpt:    keyGenOpt.ToString(),
		KeyType:      int(keyType),
		EncryptedKey: hex.EncodeToString(encryptedKeyBytes),
		Hints:        encHints,
	}

	return json.Marshal(keyFile)
}

// KeyLoader is an implementation of heimdall.keyLoader
type KeyLoader struct {
	heimdall.KeyDecryptor
	heimdall.KeyRecoverer
	heimdall.KeyDeriver
}

func NewKeyLoader(keyDecryptor heimdall.KeyDecryptor, keyRecoverer heimdall.KeyRecoverer, keyDeriver heimdall.KeyDeriver) heimdall.KeyLoader {
	return &KeyLoader{
		KeyDecryptor: keyDecryptor,
		KeyRecoverer: keyRecoverer,
		KeyDeriver:   keyDeriver,
	}
}

// LoadKey loads private key by key ID and password.
func (keyLoader *KeyLoader) LoadKey(keyId heimdall.KeyID, pwd string, keyDirPath string) (heimdall.Key, error) {
	var keyFile KeyFile

	if _, err := os.Stat(keyDirPath); os.IsNotExist(err) {
		return nil, err
	}

	if err := heimdall.KeyIDPrefixCheck(keyId); err != nil {
		return nil, err
	}

	keyPath, err := keyLoader.findKeyById(keyId, keyDirPath)
	if err != nil {
		return nil, err
	}

	jsonKeyFile, err := keyLoader.loadJsonKeyFile(keyPath)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(jsonKeyFile, &keyFile); err != nil {
		return nil, err
	}

	if err = heimdall.SKIValidCheck(keyId, keyFile.SKI); err != nil {
		return nil, err
	}

	kdfOpt := kdf.MapToOpts(keyFile.Hints.KDFInnerFileInfo)
	if !kdfOpt.IsValid() {
		return nil, ErrInvalidKDFOpt
	}

	dKey, err := keyLoader.DeriveKey([]byte(pwd), keyFile.Hints.KDFSalt, keyFile.Hints.EncInnerFileInfo.KeyLen, kdfOpt)
	if err != nil {
		return nil, err
	}

	encryptedKeyBytes, err := hex.DecodeString(keyFile.EncryptedKey)
	if err != nil {
		return nil, err
	}

	keyBytes, err := keyLoader.DecryptKey(encryptedKeyBytes, dKey)
	if err != nil {
		return nil, err
	}

	key, err := keyLoader.RecoverKeyFromByte(keyBytes, heimdall.KeyType(keyFile.KeyType), keyFile.KeyGenOpt)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// findKeyById finds key file path by key id from file names in keystore path.
func (keyLoader *KeyLoader) findKeyById(keyId string, keyDirPath string) (keyPath string, err error) {
	keyPath = ""

	files, err := ioutil.ReadDir(keyDirPath)
	if err != nil {
		return "", err
	}

	for _, file := range files {
		if strings.Compare(file.Name(), keyId) == 0 {
			keyPath = filepath.Join(keyDirPath, file.Name())
			break
		}
	}

	if len(keyPath) == 0 {
		return "", ErrWrongKeyID
	}

	return keyPath, nil
}

// loadJsonKeyFile reads json formatted KeyFile struct from file.
func (keyLoader *KeyLoader) loadJsonKeyFile(keyPath string) (jsonKeyFile []byte, err error) {
	if len(keyPath) == 0 {
		return nil, ErrEmptyKeyPath
	}

	jsonKeyFile, err = ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return jsonKeyFile, nil
}
