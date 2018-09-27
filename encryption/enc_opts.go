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

package encryption

import (
	"strconv"
	"strings"

	"github.com/it-chain/heimdall"
)

const (
	// algorithm - Ex. AES, (T)DES
	AES = "AES"
	// operation(op) mode - Ex. CTR, CBC, CFB, GCM, OFB
	CTR = "CTR"

	// full encryption options
	AES128CTR = iota
	AES192CTR
	AES256CTR
	maxEncOpt
)

var encOpts = [...]string{
	"AES_128_CTR",
	"AES_192_CTR",
	"AES_256_CTR",
	"maxEncOpt",
}

var DefaultAlgo = AES
var DefaultKeyLen = 192
var DefaultOpMode = CTR

type AESEncOpts struct {
	keyLen int
	opMode string
}

func NewAESEncOpts(keyLen int, opMode string) heimdall.EncryptOpts {
	return &AESEncOpts{
		keyLen: keyLen,
		opMode: opMode,
	}
}

// ToString returns string format of encryption algorithm with key length (ex. AES128)
func (opt AESEncOpts) ToString() string {
	return AES + heimdall.OptDelimiter + strconv.Itoa(opt.keyLen) + heimdall.OptDelimiter + opt.opMode
}

func (opt AESEncOpts) IsValid() bool {
	strFmtEncOpt := opt.ToString()

	for _, encOpt := range encOpts {
		if strFmtEncOpt == encOpt {
			return true
		}
	}

	return false
}

func (opt AESEncOpts) Algorithm() string {
	return AES
}

func (opt AESEncOpts) KeyLen() int {
	return opt.keyLen
}

func (opt AESEncOpts) ToInnerFileInfo() heimdall.EncInnerFileInfo {
	return heimdall.EncInnerFileInfo{
		Algo:   opt.Algorithm(),
		KeyLen: opt.keyLen,
		OpMode: opt.opMode,
	}
}

func StringToEncOpt(strFmtOpt string) heimdall.EncryptOpts {
	encAlgo := strings.Split(strFmtOpt, heimdall.OptDelimiter)[0]
	switch encAlgo {
	case AES:
		return stringToAESEncOpt(strFmtOpt)
		// other algorithms
	}

	return nil
}

func stringToAESEncOpt(strFmtOpt string) heimdall.EncryptOpts {
	encOpts := strings.Split(strFmtOpt, heimdall.OptDelimiter)

	keyLen, err := strconv.Atoi(encOpts[1])
	if err != nil {
		return nil
	}

	return &AESEncOpts{
		keyLen: keyLen,
		opMode: encOpts[2],
	}
}
