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
 */

package heimdall

import "github.com/it-chain/heimdall/hashing"

type KeyID string
type KeyType int

var OptDelimiter = "_"

const (
	PRIVATEKEY = iota
	PUBLICKEY
)

type KDFInnerFileInfo struct {
	KDF    string
	Params map[string]string
}

type EncInnerFileInfo struct {
	Algo   string
	KeyLen int
	OpMode string
}

// options
type Options interface {
	IsValid() bool
}

type KeyGenOpts interface {
	Options
	ToString() string
	KeySize() int
}

type SignerOpts interface {
	Options
	Algorithm() string
	HashOpt() hashing.HashOpts
	//crypto.SignerOpts
}

type KeyDerivationOpts interface {
	Options
	KDF() string
	ParamsToMap() map[string]string
	ToInnerFileInfo() KDFInnerFileInfo
}

type EncryptOpts interface {
	Options
	Algorithm() string
	KeyLen() int
	ToInnerFileInfo() EncInnerFileInfo
}
