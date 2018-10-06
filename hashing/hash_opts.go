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
	"errors"
	"hash"
)

const (
	SHA224 = "SHA224"
	SHA256 = "SHA256"
	SHA384 = "SHA384"
	SHA512 = "SHA512"
)

var ErrNotSupportedHashFunc = errors.New("not supported hash function")

type HashOpt struct {
	Name     string
	HashFunc func() hash.Hash
}

func NewHashOpt(name string) (*HashOpt, error) {
	hashOpt := new(HashOpt)
	return hashOpt, hashOpt.initHashOpt(name)
}

func (opt *HashOpt) initHashOpt(name string) error {
	switch name {
	case "SHA224":
		opt.HashFunc = sha512.New512_224
	case "SHA256":
		opt.HashFunc = sha512.New512_256
	case "SHA384":
		opt.HashFunc = sha512.New384
	case "SHA512":
		opt.HashFunc = sha512.New
	default:
		return ErrNotSupportedHashFunc
	}
	opt.Name = name

	return nil
}
