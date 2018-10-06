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

package config

import (
	"errors"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/encryption"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/it-chain/heimdall/kdf"
)

var ErrInvalidSecLv = errors.New("invalid security level")

type Config struct {
	SecLv       int
	KeyDirPath  string
	CertDirPath string
	KeyGenOpt   heimdall.KeyGenOpts
	EncOpt      *encryption.Opts
	KdfOpt      *kdf.Opts
	SigAlgo     string
	HashOpt     *hashing.HashOpt
}

// NewSimpleConfig makes configuration by input security level
func NewSimpleConfig(secLv int) (conf *Config, err error) {
	conf = new(Config)
	return conf, conf.initSimpleConfig(secLv)
}

// NewDefaultConfig makes configuration by security level 192
func NewDefaultConfig() (conf *Config, err error) {
	conf = new(Config)
	return conf, conf.initSimpleConfig(192)
}

func (conf *Config) initSimpleConfig(secLv int) error {
	switch secLv {
	case 128:
		keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP256)
		if err != nil {
			return err
		}
		conf.KeyGenOpt = keyGenOpt

		hashOpt, err := hashing.NewHashOpt(hashing.SHA256)
		if err != nil {
			return err
		}
		conf.HashOpt = hashOpt
	case 192:
		keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
		if err != nil {
			return err
		}
		conf.KeyGenOpt = keyGenOpt

		hashOpt, err := hashing.NewHashOpt(hashing.SHA384)
		if err != nil {
			return err
		}
		conf.HashOpt = hashOpt
	case 256:
		keyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP521)
		if err != nil {
			return err
		}
		conf.KeyGenOpt = keyGenOpt

		hashOpt, err := hashing.NewHashOpt(hashing.SHA512)
		if err != nil {
			return err
		}
		conf.HashOpt = hashOpt
	default:
		return ErrInvalidSecLv
	}

	conf.KeyDirPath = "./.keys"
	conf.CertDirPath = "./.certs"
	conf.SigAlgo = "ECDSA"

	encOpt, err := encryption.NewOpts("AES", secLv, "CTR")
	if err != nil {
		return err
	}
	conf.EncOpt = encOpt

	kdfOpt, err := kdf.NewOpts("SCRYPT", kdf.DefaultScryptParams)
	if err != nil {
		return err
	}
	conf.KdfOpt = kdfOpt

	return nil
}

// todo: 받을 parameter 결정..
// NewDetailConfig makes configuration by parameters corresponding to config struct members
func NewDetailConfig() (conf *Config, err error) {
	conf = new(Config)
	return conf, conf.initDetailConfig()
}

// todo: string 형태로 각각 받아서 파싱,,, 각 요소별 조건 체크..
func (conf *Config) initDetailConfig() error {
	return nil
}
