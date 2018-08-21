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

package heimdall

import (
	"errors"
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"encoding/hex"
	"io/ioutil"
	"strconv"
	"strings"
	"encoding/json"
	"crypto/rand"
)


type keystore struct {
	keyDirPath string
	kdf string
	kdfParams map[string]string
	encAlgo string
	encKeyLen int
}

// struct for encrypted key's file format.
type KeyFile struct {
	SKI string
	CurveOpt string
	EncryptedKey string
	Hints EncryptionHints
}

// struct for providing hints of encryption and key derivation function.
type EncryptionHints struct {
	EncAlgo string
	EncKeyLen int

	KDF string
	KDFParams map[string]string
	KDFSalt []byte
}

// NewKeyStore make and initialize a new keystore.
func NewKeyStore(keyDirPath string, kdf string, kdfParams map[string]string, encAlgo string, encKeyLen int) (*keystore, error) {
	keyStore := new(keystore)
	return keyStore, keyStore.init(keyDirPath, kdf, kdfParams, encAlgo, encKeyLen)
}

func (ks *keystore) init(keyDirPath string, kdf string, kdfParams map[string]string, encAlgo string, encKeyLen int) error {
	if len(keyDirPath) == 0 {
		return errors.New("invalid path - empty")
	}
	ks.keyDirPath = keyDirPath

	if len(kdf) == 0 {
		return errors.New("invalid kdf - empty")
	}
	ks.kdf = kdf

	if len(kdfParams) == 0 {
		return errors.New("invalid kdf parameters - empty")
	}
	ks.kdfParams = kdfParams

	if len(encAlgo) == 0 {
		return errors.New("invalid encryption algorithm - empty")
	}
	ks.encAlgo = encAlgo

	if encKeyLen == 0 {
		return errors.New("invalid encryption key length - 0")
	}
	ks.encKeyLen = encKeyLen

	return nil
}

// StoreKey stores private key that is encrypted by key derived from input password.
func (ks *keystore) StoreKey(pri *ecdsa.PrivateKey, pwd string) error {
	ski := hex.EncodeToString(SKIFromPubKey(&pri.PublicKey))
	keyId := PubKeyToKeyID(&pri.PublicKey)

	curveOpt := StringToCurveOpt("secp" + strconv.Itoa(pri.Curve.Params().BitSize) + "r1").String()
	if curveOpt == UNKNOWN.String() {
		return errors.New("invalid private key - not in list of supported curve")
	}

	keyFilePath, err := ks.makeKeyFilePath(keyId)
	if err != nil {
		return err
	}

	salt := make([]byte, 8)
	_, err = rand.Read(salt)
	if err != nil {
		return err
	}

	dKey, err := DeriveKeyFromPwd(ks.kdf, []byte(pwd), salt, ks.encKeyLen, ks.kdfParams)
	if err != nil {
		return err
	}

	encryptedKeyBytes, err := EncryptPriKey(pri, dKey)
	if err != nil {
		return err
	}

	jsonKeyFile, err := ks.makeJsonKeyFile(ski, curveOpt, encryptedKeyBytes, salt)
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
func (ks *keystore) makeKeyFilePath(keyFileName string) (string, error) {
	if _, err := os.Stat(ks.keyDirPath); os.IsNotExist(err) {
		err = os.MkdirAll(ks.keyDirPath, 0755)
		if err != nil {
			return "", err
		}
	}

	return filepath.Join(ks.keyDirPath, keyFileName), nil
}

// makeJsonKeyFile marshals keyFile struct to json format.
func (ks *keystore) makeJsonKeyFile(ski string, curveOpt string, encryptedKeyBytes []byte, kdfSalt []byte) ([]byte, error) {
	encHints := EncryptionHints{
		EncAlgo: ks.encAlgo,
		EncKeyLen: ks.encKeyLen,
		KDF: ks.kdf,
		KDFParams: ks.kdfParams,
		KDFSalt: kdfSalt,
	}

	keyFile := KeyFile{
		SKI: ski,
		CurveOpt: curveOpt,
		EncryptedKey: hex.EncodeToString(encryptedKeyBytes),
		Hints: encHints,
	}

	return json.Marshal(keyFile)
}

// LoadKey loads private key by key ID and password.
func (ks *keystore) LoadKey(keyId string, pwd string) (*ecdsa.PrivateKey, error) {
	var keyFile KeyFile

	if _, err := os.Stat(ks.keyDirPath); os.IsNotExist(err) {
		return nil, errors.New("invalid keystore path - not exist")
	}

	if err := KeyIDPrefixCheck(keyId); err != nil {
		return nil, err
	}

	keyPath, err := ks.findKeyById(keyId)
	if err != nil {
		return nil, err
	}

	jsonKeyFile, err := ks.loadJsonKeyFile(keyPath)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(jsonKeyFile, &keyFile); err != nil {
		return nil, err
	}

	if err = SKIValidCheck(keyId, keyFile.SKI); err != nil {
		return nil, err
	}

	dKey, err := DeriveKeyFromPwd(keyFile.Hints.KDF, []byte(pwd), keyFile.Hints.KDFSalt, keyFile.Hints.EncKeyLen, keyFile.Hints.KDFParams)
	if err != nil {
		return nil, err
	}

	encryptedKeyBytes, err := hex.DecodeString(keyFile.EncryptedKey)
	if err != nil {
		return nil, err
	}

	pri, err := DecryptPriKey(encryptedKeyBytes, dKey, StringToCurveOpt(keyFile.CurveOpt))
	if err != nil {
		return nil, err
	}

	return pri, nil
}

// findKeyById finds key file path by key id from file names in keystore path.
func (ks *keystore) findKeyById(keyId string) (keyPath string, err error) {
	keyPath = ""

	files, err := ioutil.ReadDir(ks.keyDirPath)
	if err != nil {
		return "", errors.New("invalid keystore path - failed to read directory path")
	}

	for _, file := range files {
		if strings.Compare(file.Name(), keyId) == 0 {
			keyPath = filepath.Join(ks.keyDirPath, file.Name())
			break
		}
	}

	if len(keyPath) == 0 {
		return "", errors.New("wrong key id - failed to find key using keyId")
	}

	return keyPath, nil
}

// loadJsonKeyFile reads json formatted KeyFile struct from file.
func (ks *keystore) loadJsonKeyFile(keyPath string) (jsonKeyFile []byte, err error) {
	if len(keyPath) == 0 {
		return nil, errors.New("invalid keyPath - keyPath empty")
	}

	jsonKeyFile, err = ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return jsonKeyFile, nil
}
