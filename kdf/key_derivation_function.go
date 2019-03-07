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

// This file provides function for deriving a key from password for encrypting private key.

package kdf

import (
	"hash"
	"strconv"

	"github.com/DE-labtory/heimdall/hashing"
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
func deriveKeyWithScrypt(pwd []byte, salt []byte, keyLen int, scryptParams map[string]string) (dKey []byte, err error) {
	N, R, P, err := scryptParamsFromMap(scryptParams)
	if err != nil {
		return nil, err
	}

	return scrypt.Key(pwd, salt, N, R, P, keyLen/8)
}

func scryptParamsFromMap(scryptParams map[string]string) (N, R, P int, err error) {
	N, err = strconv.Atoi(scryptParams["N"])
	if N <= 0 {
		return -1, -1, -1, ErrScryptNValueZeroOrNegative
	}
	if err != nil {
		return -1, -1, -1, err
	}

	R, err = strconv.Atoi(scryptParams["R"])
	if R <= 0 {
		return -1, -1, -1, ErrScryptRValueZeroOrNegative
	}
	if err != nil {
		return -1, -1, -1, err
	}

	P, err = strconv.Atoi(scryptParams["P"])
	if P <= 0 {
		return -1, -1, -1, ErrScryptPValueZeroOrNegative
	}
	if err != nil {
		return -1, -1, -1, err
	}

	return N, R, P, nil
}

func deriveKeyWithPbkdf2(pwd []byte, salt []byte, keyLen int, pbkdf2Params map[string]string) (dKey []byte, err error) {
	iteration, hashFunction, err := pbkdf2ParamsFromMap(pbkdf2Params)
	if err != nil {
		return nil, err
	}

	return pbkdf2.Key(pwd, salt, iteration, keyLen/8, hashFunction), nil
}

func pbkdf2ParamsFromMap(pbkdf2Params map[string]string) (iteration int, hashFunction func() hash.Hash, err error) {
	iteration, err = strconv.Atoi(pbkdf2Params["iteration"])
	if err != nil {
		return -1, nil, err
	}
	if iteration <= 0 {
		return -1, nil, ErrPbkdf2IterationValueZeroOrNegative
	}

	hashOpt, err := hashing.NewHashOpt(pbkdf2Params["hashOpt"])
	if err != nil {
		return -1, nil, err
	}
	hashFunction = hashOpt.HashFunc

	return iteration, hashFunction, err
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
