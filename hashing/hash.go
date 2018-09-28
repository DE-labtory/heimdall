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

// This file implements hashing manager for hashing process.

package hashing

import (
	"errors"
)

var ErrTargetDataNil = "hashing target data should not be nil"

// Hash hashes the input data.
func Hash(data []byte, opt HashOpts) ([]byte, error) {
	if data == nil {
		return nil, errors.New(ErrTargetDataNil)
	}

	hashFunc := opt.HashFunction()()

	hashFunc.Write(data)
	return hashFunc.Sum(nil), nil
}
