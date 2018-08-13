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

package heimdall

import (
	"golang.org/x/crypto/scrypt"
	"errors"
	"strconv"
)

const (
	KDFName = "scrypt"

	// N should highest power of 2 that key derived in 100ms.
	ScryptN = "32768" // 1 << 15 (2^15)
	// Parallelization parameter; a positive integer satisfying p ≤ (232− 1) * hLen / MFLen.
	ScryptP = "1"

	// blocksize parameter : fine-tune sequential memory read size and performance. (8 is commonly used)
	ScryptR = "8"
	// Desired length of key in bytes
	ScryptKeyLen = "32"
)

// DeriveKeyFromPwd derives a key from input password.
func DeriveKeyFromPwd(KDFName string, pwd []byte, salt []byte, keyLen int, KDFParams map[string]string) (dKey []byte, err error) {

	if KDFName == SCRYPT {
		// The params N, r, p are cost parameters, and 32768, 8, 1 are recommended parameters for interactive login as of 2017.
		n, err := strconv.Atoi(KDFParams["n"])
		if err != nil {
			return nil, err
		}

		r, err := strconv.Atoi(KDFParams["r"])
		if err != nil {
			return nil, err
		}

		p, err := strconv.Atoi(KDFParams["p"])
		if err != nil {
			return nil, err
		}

		return scrypt.Key(pwd, salt, n, r, p, keyLen)

	} else if KDFName == PBKDF2{
		return nil, errors.New("invalid KDF - not supported")
	} else if KDFName == BCRYPT {
		return nil, errors.New("invalid KDF - not supported")
	} else {
		return nil, errors.New("invalid KDF - not supported")
	}

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