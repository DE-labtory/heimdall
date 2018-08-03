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

// This file implements hash manager for hashing process.

package heimdall

import (
	"crypto/sha1"
	"crypto/sha512"
	"errors"
	"hash"
)

// Hash hashes the input data.
func Hash(data []byte, tail []byte, opts HashOpts) ([]byte, error) {

	if data == nil {
		return nil, errors.New("data should not be NIL")
	}

	var selectedHash hash.Hash

	switch opts {
	case SHA1:
		selectedHash = sha1.New()
	case SHA224:
		selectedHash = sha512.New512_224()
	case SHA256:
		selectedHash = sha512.New512_256()
	case SHA384:
		selectedHash = sha512.New384()
	case SHA512:
		selectedHash = sha512.New()
	default:
		return nil, errors.New("invalid hash opts")
	}

	selectedHash.Write(data)
	return selectedHash.Sum(tail), nil

}
