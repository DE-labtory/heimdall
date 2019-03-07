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

package kdf

import (
	"errors"

	"github.com/DE-labtory/heimdall/hashing"
)

// todo: 각 파라미터별 제한 두기 (최소 / 최대)

// Errors
var ErrKdfNotSupported = errors.New("kdf not supported")

var ErrScryptParamsNumber = errors.New("number of scrypt parameters should be 3")
var ErrScryptNValueNotExist = errors.New("input parameters have no [N], scrypt parameters should have [N]")
var ErrScryptNValueZeroOrNegative = errors.New("scrypt [N] should be non-zero and positive value")
var ErrScryptRValueNotExist = errors.New("input parameters have no [R], scrypt parameters should have [R]")
var ErrScryptRValueZeroOrNegative = errors.New("scrypt [R] should be non-zero and positive value")
var ErrScryptPValueNotExist = errors.New("input parameters have no [P], scrypt parameters should have [P]")
var ErrScryptPValueZeroOrNegative = errors.New("scrypt [P] should be non-zero and positive value")

var ErrPbkdf2ParamsNumber = errors.New("number of pbkdf2 parameters should be 2")
var ErrPbkdf2IterationValueNotExist = errors.New("input parameters have no [iteration], pbkdf2 parameters should have [iteration]")
var ErrPbkdf2IterationValueZeroOrNegative = errors.New("pbkdf2 [iteration] should be non-zero and positive value")
var ErrPbkdf2HashOptValueNotExist = errors.New("input parameters have no [hashOpt], pbkdf2 parameters should have [hashOpt]")
var ErrPbkdf2HashOptValueZeroOrNegative = errors.New("invalid hash option [hashOpt]")

// Default scrypt Parameters
// references
// https://media.readthedocs.org/pdf/cryptography/stable/cryptography.pdf
// https://godoc.org/golang.org/x/crypto/scrypt
// https://blog.filippo.io/the-scrypt-parameters/
// N is CPU/Memory cost parameter. It should highest power of 2 that key derived in 100ms.
var DefaultScryptN = "1048576" // 1 << 20 (2^20)
// R(blocksize parameter) : fine-tune sequential memory read size and performance. (8 is commonly used)
var DefaultScryptR = "8"

// P(Parallelization parameter) : a positive integer satisfying p ≤ (232− 1) * hLen / MFLen.
var DefaultScryptP = "1"

var DefaultScryptParams = map[string]string{
	"N": DefaultScryptN,
	"R": DefaultScryptR,
	"P": DefaultScryptP,
}

// Default PBKDF2 iteration count
// NIST recommended this should be large as verification server performance will allow
// references
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
var DefaultPbkdf2Iteration = "10000000"

var DefaultPbkdf2Params = map[string]string{
	"iteration": DefaultPbkdf2Iteration,
	"hashOpt":   hashing.SHA384,
}

// Default Salt Size (byte)
var DefaultSaltSize = 8

// Note: salt have to be unique, so do not use this for real implementation.
var TestSalt = []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}

// supported Key Derivation Functions
const (
	SCRYPT = "SCRYPT"
	PBKDF2 = "PBKDF2"
)

type Opts struct {
	KdfName   string
	KdfParams map[string]string
}

func NewOpts(kdfName string, kdfParams map[string]string) (*Opts, error) {
	opt := new(Opts)
	return opt, opt.initOpt(kdfName, kdfParams)
}

func (opt *Opts) initOpt(kdfName string, kdfParams map[string]string) error {
	switch kdfName {
	case SCRYPT:
		opt.KdfName = kdfName
		return opt.initScryptParams(kdfParams)
	case PBKDF2:
		opt.KdfName = kdfName
		return opt.initPbkdf2Params(kdfParams)
	default:
		return ErrKdfNotSupported
	}

	return nil
}

// todo: 좀 더 자세한 제한 수치 (N, R, P)
func (opt *Opts) initScryptParams(kdfParams map[string]string) error {
	if len(kdfParams) != 3 {
		return ErrScryptParamsNumber
	}

	_, exists := kdfParams["N"]
	if !exists {
		return ErrScryptNValueNotExist
	}

	_, exists = kdfParams["R"]
	if !exists {
		return ErrScryptRValueNotExist
	}

	_, exists = kdfParams["P"]
	if !exists {
		return ErrScryptPValueNotExist
	}

	opt.KdfParams = kdfParams

	return nil
}

// todo: 자세한 제한 수치 (iteration, hashOpt)
func (opt *Opts) initPbkdf2Params(kdfParams map[string]string) error {
	if len(kdfParams) != 2 {
		return ErrPbkdf2ParamsNumber
	}

	_, exists := kdfParams["iteration"]
	if !exists {
		return ErrPbkdf2IterationValueNotExist
	}

	_, exists = kdfParams["hashOpt"]
	if !exists {
		return ErrPbkdf2HashOptValueNotExist
	}

	opt.KdfParams = kdfParams

	return nil
}
