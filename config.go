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

// This file provides configuration of parameters for signing and verifying.

package heimdall

import (
	"errors"
	"strings"
)

type Config struct {
	SecLv int
	KeyDirPath string
	CertDirPath string
	EncAlgo string
	SigAlgo string
	Kdf string
	KdfParams map[string]string
	CurveOpt CurveOpts
	HashOpt HashOpts
	EncKeyLength int
}

// NewConfig makes configuration struct using entered parameters.
func NewConfig(secLv int, keyDirPath, certDirPath, encAlgo, sigAlgo, kdf string, kdfParams map[string]string) (conf *Config, err error) {
	conf = new(Config)
	return conf, conf.initConfig(secLv, keyDirPath, certDirPath, encAlgo, sigAlgo, kdf, kdfParams)
}

func NewDefaultConfig() (conf *Config) {
	conf = new(Config)
	conf.initDefaultConfig()
	return conf
}

// initConfig initiates configuration struct using entered parameters.
func (conf *Config) initConfig(secLv int, keyDirPath, certDirPath, encAlgo, sigAlgo, kdf string, kdfParams map[string]string) error {
	if len(keyDirPath) == 0 {
		return errors.New("invalid key directory path - empty")
	}
	conf.KeyDirPath = keyDirPath

	if len(certDirPath) == 0 {
		return errors.New("invalid certificate directory path - empty")
	}
	conf.CertDirPath = certDirPath

	if len(encAlgo) == 0 {
		return errors.New("invalid encryption algorithm - empty")
	} else if encAlgo = strings.ToUpper(encAlgo); encAlgo != "AES-CTR" {
		return errors.New("invalid encryption algorithm - not supported")
	}
	conf.EncAlgo = encAlgo

	if len(sigAlgo) == 0 {
		return errors.New("invalid signature algorithm - empty")
	} else if sigAlgo = strings.ToUpper(sigAlgo); sigAlgo != "ECDSA" {
		return errors.New("invalid signature algorithm - not supported")
	}
	conf.SigAlgo = sigAlgo

	if len(kdf) == 0 {
		errors.New("invalid key derivation function - empty")
	} else if kdf = strings.ToLower(kdf); kdf != "scrypt" && kdf != "bcrypt" && kdf != "pbkdf2" {
		return errors.New("invalid key derivation function - not supported")
	}
	conf.Kdf = kdf

	if len(kdfParams) == 0 {
		return errors.New("invalid key derivation function parameters - empty")
	}
	conf.KdfParams = kdfParams

	switch secLv {
	case 112:
		conf.initBySecLv112()
		break

	case 128:
		conf.initBySecLv128()
		break

	case 192:
		conf.initBySecLv192()
		break

	case 256:
		conf.initBySecLv256()
		break

	default:
		return errors.New("invalid security level - not supported")
	}
	conf.SecLv = secLv

	return nil
}

func (conf *Config) initDefaultConfig() {
	conf.SecLv = 192
	conf.KeyDirPath = TestKeyDir
	conf.CertDirPath = TestCertDir
	conf.Kdf = "scrypt"
	conf.SigAlgo = "ECDSA"
	conf.EncAlgo = "AES-CTR"
	conf.KdfParams = DefaultScrpytParams
	conf.initBySecLv192()
}

// initBySecLv112 sets hash type, elliptic curve type, key length for encryption corresponding to 112bits of security level.
func (conf *Config) initBySecLv112() {
	conf.HashOpt = SHA224
	conf.CurveOpt = SECP224R1
	conf.EncKeyLength = int(112 / 8)
}

// initBySecLv128 sets hash type, elliptic curve type, key length for encryption corresponding to 128bits of security level.
func (conf *Config) initBySecLv128() {
	conf.HashOpt = SHA256
	conf.CurveOpt = SECP256R1
	conf.EncKeyLength = int(128 / 8)
}

// initBySecLv192 sets hash type, elliptic curve type, key length for encryption corresponding to 192bits of security level.
func (conf *Config) initBySecLv192() {
	conf.HashOpt = SHA384
	conf.CurveOpt = SECP384R1
	conf.EncKeyLength = int(192 / 8)
}

// initBySecLv256 sets hash type, elliptic curve type, key length for encryption corresponding to 256bits of security level.
func (conf *Config) initBySecLv256() {
	conf.HashOpt = SHA512
	conf.CurveOpt = SECP521R1
	conf.EncKeyLength = int(256 / 8)
}

