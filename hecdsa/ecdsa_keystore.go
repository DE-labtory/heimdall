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

// This file provides functions for storing and loading ECDSA key pair.

package hecdsa

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/DE-labtory/heimdall"
	"github.com/DE-labtory/heimdall/encryption"
	"github.com/DE-labtory/heimdall/kdf"
	"github.com/DE-labtory/iLogger"
)

var ErrWrongKeyID = errors.New("wrong key id - failed to find key using key ID")
var ErrEmptyKeyPath = errors.New("invalid keyPath - keyPath empty")
var ErrMultiplePriKey = errors.New("private key in directory should be one")

// struct for encrypted key's file format.
type KeyFile struct {
	SKI          []byte
	EncryptedKey string
	Hints        *EncryptionHints
}

// struct for providing hints of encryption and key derivation function.
type EncryptionHints struct {
	EncOpt  *encryption.Opts
	KDFOpt  *kdf.Opts
	KDFSalt []byte
}

func StorePriKeyWithoutPwd(key heimdall.PriKey, keyDirPath string) error {
	keyId := key.ID()

	keyFilePath, err := makeKeyFilePath(keyId, keyDirPath)
	if err != nil {
		return err
	}

	files, err := ioutil.ReadDir(keyDirPath)
	if err != nil {
		return err
	} else if len(files) > 0 {
		for _, file := range files {
			os.Remove(filepath.Join(keyDirPath, file.Name()))
		}
	}

	keyBytes, err := key.ToByte()
	if err != nil {
		return err
	}

	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		err = ioutil.WriteFile(keyFilePath, keyBytes, 0700)
		if err != nil {
			return err
		}
	}

	return nil
}

// StorePriKey stores private key with password.
func StorePriKey(key heimdall.PriKey, pwd, keyDirPath string, encOpt *encryption.Opts, kdfOpt *kdf.Opts) error {
	ski := key.SKI()
	keyId := key.ID()

	keyFilePath, err := makeKeyFilePath(keyId, keyDirPath)
	if err != nil {
		return err
	}

	files, err := ioutil.ReadDir(keyDirPath)
	if err != nil {
		return err
	} else if len(files) > 0 {
		iLogger.Info(nil, "[Heimdall] private key already exist - will be overwritten")

		for _, file := range files {
			os.Remove(filepath.Join(keyDirPath, file.Name()))
		}
	}

	salt := make([]byte, 8)
	_, err = rand.Read(salt)
	if err != nil {
		return err
	}

	dKey, err := kdf.DeriveKey([]byte(pwd), salt, encOpt.KeyLen, kdfOpt)
	if err != nil {
		return err
	}

	encryptedKeyBytes, err := encryption.EncryptKey(key, dKey, encOpt)
	if err != nil {
		return err
	}

	encHints := makeEncryptionHints(encOpt, kdfOpt, salt)

	jsonKeyFile, err := makeJsonKeyFile(encHints, ski, encryptedKeyBytes)
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

// StorePubKey stores public key.
func StorePubKey(key heimdall.PubKey, keyDirPath string) error {
	keyId := key.ID()

	keyFilePath, err := makeKeyFilePath(keyId, keyDirPath)
	if err != nil {
		return err
	}

	keyBytes, err := key.ToByte()
	if err != nil {
		return err
	}

	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		err = ioutil.WriteFile(keyFilePath, keyBytes, 0700)
		if err != nil {
			return err
		}
	}

	return nil
}

// makeKeyFilePath makes key file path (absolute) of the key file.
func makeKeyFilePath(keyFileName string, keyDirPath string) (string, error) {
	if _, err := os.Stat(keyDirPath); os.IsNotExist(err) {
		err = os.MkdirAll(keyDirPath, 0755)
		if err != nil {
			iLogger.Errorf(nil, "[Heimdall] %s", err)
			return "", err
		}
	}

	return filepath.Join(keyDirPath, keyFileName), nil
}

// makeEncryptionHints makes encryption hints for decryption later.
func makeEncryptionHints(encOpt *encryption.Opts, kdfOpt *kdf.Opts, kdfSalt []byte) *EncryptionHints {
	return &EncryptionHints{
		EncOpt:  encOpt,
		KDFOpt:  kdfOpt,
		KDFSalt: kdfSalt,
	}
}

// makeJsonKeyFile marshals keyFile struct to json format.
func makeJsonKeyFile(encHints *EncryptionHints, ski []byte, encryptedKeyBytes []byte) ([]byte, error) {
	keyFile := KeyFile{
		SKI:          ski,
		EncryptedKey: hex.EncodeToString(encryptedKeyBytes),
		Hints:        encHints,
	}

	return json.Marshal(keyFile)
}

func LoadPriKeyWithoutPwd(keyDirPath string) (heimdall.PriKey, error) {
	if _, err := os.Stat(keyDirPath); os.IsNotExist(err) {
		iLogger.Error(nil, "[Heimdall] Key dir not exist")
		return nil, err
	}

	files, err := ioutil.ReadDir(keyDirPath)
	if err != nil {
		iLogger.Error(nil, "[Heimdall] Error during read key dir")
		return nil, err
	} else if len(files) > 1 {
		iLogger.Error(nil, "[Heimdall] Multiple private key file detected")
		return nil, ErrMultiplePriKey
	} else if len(files) < 1 {
		iLogger.Error(nil, "[Heimdall] Empty key path")
		return nil, ErrEmptyKeyPath
	}

	keyPath := filepath.Join(keyDirPath, files[0].Name())
	keyBytes, err := loadKeyFile(keyPath)
	if err != nil {
		iLogger.Error(nil, "[Heimdall] Error during load key file")
		return nil, err
	}

	recoverer := &KeyRecoverer{}
	key, err := recoverer.RecoverKeyFromByte(keyBytes, true)
	if err != nil {
		iLogger.Error(nil, "error during recover key")
		return nil, err
	}

	return key.(heimdall.PriKey), nil
}

// LoadPriKey loads private key with password.
func LoadPriKey(keyDirPath, pwd string) (heimdall.PriKey, error) {
	var keyFile KeyFile

	if _, err := os.Stat(keyDirPath); os.IsNotExist(err) {
		return nil, err
	}

	files, err := ioutil.ReadDir(keyDirPath)
	if err != nil {
		return nil, err
	} else if len(files) > 1 {
		return nil, ErrMultiplePriKey
	} else if len(files) < 1 {
		return nil, ErrEmptyKeyPath
	}

	keyPath := filepath.Join(keyDirPath, files[0].Name())
	jsonKeyFile, err := loadKeyFile(keyPath)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(jsonKeyFile, &keyFile); err != nil {
		return nil, err
	}

	kdfOpt, err := kdf.NewOpts(keyFile.Hints.KDFOpt.KdfName, keyFile.Hints.KDFOpt.KdfParams)
	if err != nil {
		return nil, err
	}

	encOpt, err := encryption.NewOpts(keyFile.Hints.EncOpt.Algorithm, keyFile.Hints.EncOpt.KeyLen, keyFile.Hints.EncOpt.OpMode)
	if err != nil {
		return nil, err
	}

	dKey, err := kdf.DeriveKey([]byte(pwd), keyFile.Hints.KDFSalt, encOpt.KeyLen, kdfOpt)
	if err != nil {
		return nil, err
	}

	encryptedKeyBytes, err := hex.DecodeString(keyFile.EncryptedKey)
	if err != nil {
		return nil, err
	}

	keyBytes, err := encryption.DecryptKey(encryptedKeyBytes, dKey, encOpt)
	if err != nil {
		return nil, err
	}

	recoverer := &KeyRecoverer{}
	key, err := recoverer.RecoverKeyFromByte(keyBytes, true)
	if err != nil {
		return nil, err
	}

	return key.(heimdall.PriKey), nil
}

// LoadPubKey loads public key by key ID.
func LoadPubKey(keyId heimdall.KeyID, keyDirPath string) (heimdall.PubKey, error) {
	if _, err := os.Stat(keyDirPath); os.IsNotExist(err) {
		return nil, err
	}

	if err := heimdall.KeyIDPrefixCheck(keyId); err != nil {
		return nil, err
	}

	keyPath, err := findKeyById(keyId, keyDirPath)
	if err != nil {
		return nil, err
	}

	keyBytes, err := loadKeyFile(keyPath)
	if err != nil {
		return nil, err
	}

	recoverer := &KeyRecoverer{}
	key, err := recoverer.RecoverKeyFromByte(keyBytes, false)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// findKeyById finds key file path by key id from file names in keystore path.
func findKeyById(keyId string, keyDirPath string) (keyPath string, err error) {
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
func loadKeyFile(keyPath string) (keyBytes []byte, err error) {
	if len(keyPath) == 0 {
		return nil, ErrEmptyKeyPath
	}

	keyBytes, err = ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return keyBytes, nil
}
