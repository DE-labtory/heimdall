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
	"github.com/it-chain/heimdall/hashing"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func DeriveKey(pwd []byte, salt []byte, keyLen int, kdfOpt *Opts) (dKey []byte, err error) {
	switch kdfOpt.KdfName {
	case SCRYPT:
		return deriveKeyWithScrypt(pwd, salt, keyLen, kdfOpt.KdfParams)
	case PBKDF2:
		return deriveKeyWithPbkdf2(pwd, salt, keyLen, kdfOpt.KdfParams)
	default:
		return nil, ErrKdfNotSupported
	}
}

// DeriveKey derives a key from input password.
func deriveKeyWithScrypt(pwd []byte, salt []byte, keyLen int, scryptParams map[string]int) (dKey []byte, err error) {
	return scrypt.Key(pwd, salt, scryptParams["N"], scryptParams["R"], scryptParams["P"], keyLen/8)
}

func deriveKeyWithPbkdf2(pwd []byte, salt []byte, keyLen int, pbkdf2Params map[string]int) (dKey []byte, err error) {
	return pbkdf2.Key(pwd, salt, pbkdf2Params["iteration"], keyLen/8, hashing.HashOpts(pbkdf2Params["hashOpt"]).HashFunction()), nil
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
