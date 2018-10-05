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

// This file provides ECDSA key related functions.

package heimdall

import (
	"errors"
	"strings"

	"github.com/btcsuite/btcutil/base58"
)

type KeyRecoverer interface {
	RecoverKeyFromByte(keyBytes []byte, isPrivate bool) (Key, error)
}

type Key interface {
	ID() KeyID
	SKI() []byte
	ToByte() []byte
	KeyGenOpt() KeyGenOpts
	IsPrivate() bool
}

type PriKey interface {
	Key
	Clear()
	PublicKey() PubKey
	//crypto.Signer
}

type PubKey interface {
	Key
}

// Key ID prefix
const KeyIDPrefix = "IT"

// SKIToKeyID obtains key ID from SKI(Subject Key Identifier).
func SKIToKeyID(ski []byte) string {
	return KeyIDPrefix + base58.Encode(ski)
}

// SKIValidCheck checks if input SKI is corresponding to key id.
func SKIValidCheck(keyId string, ski []byte) error {
	if SKIToKeyID(ski) != keyId {
		return errors.New("invalid SKI - SKI is not correspond to input key ID")
	}

	return nil
}

// KeyIDPrefixCheck checks if input key id has right prefix.
func KeyIDPrefixCheck(keyId string) error {
	if strings.HasPrefix(keyId, KeyIDPrefix) != true {
		return errors.New("invalid key ID - prefix should be 'IT'")
	}

	return nil
}
