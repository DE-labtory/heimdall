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
 */

package encryption

import (
	"errors"
	"strconv"

	"github.com/DE-labtory/heimdall"
)

var ErrAlgorithmNotSupported = errors.New("entered algorithm is not supported")
var ErrKeyLengthNotSupported = errors.New("entered key length is not supported")
var ErrOperationModeNotSupported = errors.New("entered operation mode is not supported")

const (
	// algorithm - Ex. AES, (T)DES
	AES = "AES"
	// operation(op) mode - Ex. CTR, CBC, CFB, GCM, OFB
	CTR = "CTR"
)

var DefaultAlgo = AES
var DefaultKeyLen = 192
var DefaultOpMode = CTR

type Opts struct {
	Algorithm string
	KeyLen    int
	OpMode    string
}

func NewOpts(algorithm string, keyLen int, opMode string) (encOpt *Opts, err error) {
	encOpt = new(Opts)
	return encOpt, encOpt.initOpts(algorithm, keyLen, opMode)
}

func (opt *Opts) initOpts(algorithm string, keyLen int, opMode string) error {
	// algorithm
	switch algorithm {
	case AES:
		opt.Algorithm = algorithm
	default:
		return ErrAlgorithmNotSupported
	}

	// key length
	switch keyLen {
	case 128:
		opt.KeyLen = keyLen
	case 192:
		opt.KeyLen = keyLen
	case 256:
		opt.KeyLen = keyLen
	default:
		return ErrKeyLengthNotSupported
	}

	// operation mode
	switch opMode {
	case CTR:
		opt.OpMode = opMode
	default:
		return ErrOperationModeNotSupported
	}

	return nil
}

// ToString returns string format of encryption algorithm with key length (ex. AES128)
func (opt *Opts) ToString() string {
	return opt.Algorithm + heimdall.OptDelimiter + strconv.Itoa(opt.KeyLen) + heimdall.OptDelimiter + opt.OpMode
}
