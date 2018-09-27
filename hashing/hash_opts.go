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

// This file provides hashing options.

package hashing

import (
	"crypto/sha512"
	"hash"
)

// HashOpts represents hashing options with integer.
type HashOpts uint

const (
	SHA224 HashOpts = iota
	SHA256
	SHA384
	SHA512
	MaxHashOpt
)

var hashes = [...]string{
	"SHA224",
	"SHA256",
	"SHA384",
	"SHA512",
}

// ToString obtains hashing's name as string format from hashing option type.
func (opt HashOpts) ToString() string {
	if !opt.IsValid() {
		return "invalid hashing option - not supported"
	}

	return hashes[opt]
}

// ValidCheck checks the hashing option is valid or not.
func (opt HashOpts) IsValid() bool {
	return opt >= 0 && opt < MaxHashOpt
}

func (opt HashOpts) HashFunction() func() hash.Hash {
	switch opt {
	case SHA224:
		return sha512.New512_224
	case SHA256:
		return sha512.New512_256
	case SHA384:
		return sha512.New384
	case SHA512:
		return sha512.New
	default:
		return nil
	}
}

func StringToHashOpts(strFormatOpt string) HashOpts {
	for idx, opts := range hashes {
		if strFormatOpt == opts {
			return HashOpts(idx)
		}
	}

	return MaxHashOpt
}
