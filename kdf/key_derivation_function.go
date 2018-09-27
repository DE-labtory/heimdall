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

// This file provides function for deriving a key from password for encrypting private key.

package kdf

import (
	"github.com/it-chain/heimdall"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type ScryptKeyDeriver struct {
}

// DeriveKey derives a key from input password.
func (keyDeriver *ScryptKeyDeriver) DeriveKey(pwd []byte, salt []byte, keyLen int, opt heimdall.KeyDerivationOpts) (dKey []byte, err error) {
	return scrypt.Key(pwd, salt, opt.(*ScryptOpts).n, opt.(*ScryptOpts).r, opt.(*ScryptOpts).p, keyLen/8)
}

type Pbkdf2KeyDeriver struct {
}

func (keyDeriver *Pbkdf2KeyDeriver) DeriveKey(pwd []byte, salt []byte, keyLen int, opt heimdall.KeyDerivationOpts) (dKey []byte, err error) {
	return pbkdf2.Key(pwd, salt, opt.(*Pbkdf2Opts).iteration, keyLen/8, opt.(*Pbkdf2Opts).hashOpt.HashFunction()), nil
}

// TODO: json marshalling make integer type to float64 type,,,,
// TODO: I make the all params as string type before calling KDF, but it should be solved fundamentally (unnecessary Atoi function)
// TODO: Below is solution for this problem in ethereum.
//func float64ToInt(intParam interface{}) int {
//	res, ok := intParam.(int)
//	if !ok {
//		res = int(intParam.(float64))
//	}
//	return res
//}
