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

package kdf

import (
	"strconv"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/hashing"
)

// todo: 각 파라미터별 제한 두기 (최소 / 최대)

// Default scrypt Parameters
// references
// https://media.readthedocs.org/pdf/cryptography/stable/cryptography.pdf
// https://godoc.org/golang.org/x/crypto/scrypt
// https://blog.filippo.io/the-scrypt-parameters/
// N is CPU/Memory cost parameter. It should highest power of 2 that key derived in 100ms.
var DefaultScryptN = 1048576 // 1 << 20 (2^20)
// R(blocksize parameter) : fine-tune sequential memory read size and performance. (8 is commonly used)
var DefaultScryptR = 8

// P(Parallelization parameter) : a positive integer satisfying p ≤ (232− 1) * hLen / MFLen.
var DefaultScryptP = 1

// Default PBKDF2 iteration count
// NIST recommended this should be large as verification server performance will allow
// references
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
var DefaultPbkdf2Iteration = 10000000

// Default Salt Size (byte)
var DefaultSaltSize = 8

// Note: salt have to be unique, so do not use this for real implementation.
var TestSalt = []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}

// supported Key Derivation Functions
const (
	Scrypt = "SCRYPT"
	Pbkdf2 = "PBKDF2"
)

var kdfs = [...]string{
	"SCRYPT",
	"PBKDF2",
}

type ScryptOpts struct {
	n int
	r int
	p int
}

func NewScryptOpts(n, r, p int) heimdall.KeyDerivationOpts {
	return &ScryptOpts{
		n: n,
		r: r,
		p: p,
	}
}

// todo: 멤버 (N, R, P) 각각 제한 수치 찾아서 구현
func (opt ScryptOpts) IsValid() bool {
	return true
}

func (opt ScryptOpts) KDF() string {
	return Scrypt
}

func (opt ScryptOpts) ParamsToMap() map[string]string {
	params := make(map[string]string, 3)
	params["N"] = strconv.Itoa(opt.n)
	params["R"] = strconv.Itoa(opt.r)
	params["P"] = strconv.Itoa(opt.p)

	return params
}

func (opt ScryptOpts) ToInnerFileInfo() heimdall.KDFInnerFileInfo {
	return heimdall.KDFInnerFileInfo{
		KDF:    opt.KDF(),
		Params: opt.ParamsToMap(),
	}
}

type Pbkdf2Opts struct {
	iteration int
	hashOpt   hashing.HashOpts
}

func NewPbkdf2Opts(iteration int, hashOpt hashing.HashOpts) heimdall.KeyDerivationOpts {
	return &Pbkdf2Opts{
		iteration: iteration,
		hashOpt:   hashOpt,
	}
}

// todo: 멤버 각각 제한 수치 찾아서 구현
func (opt Pbkdf2Opts) IsValid() bool {
	return true
}

func (opt Pbkdf2Opts) KDF() string {
	return Pbkdf2
}

func (opt Pbkdf2Opts) ParamsToMap() map[string]string {
	params := make(map[string]string, 2)
	params["iteration"] = strconv.Itoa(opt.iteration)
	params["hashOpt"] = strconv.Itoa(int(opt.hashOpt))

	return params
}

func (opt Pbkdf2Opts) ToInnerFileInfo() heimdall.KDFInnerFileInfo {
	return heimdall.KDFInnerFileInfo{
		KDF:    opt.KDF(),
		Params: opt.ParamsToMap(),
	}
}

func MapToOpts(kdfInfo heimdall.KDFInnerFileInfo) heimdall.KeyDerivationOpts {
	switch kdfInfo.KDF {
	case Scrypt:
		return mapToScryptOpts(kdfInfo.Params)
	case Pbkdf2:
		return mapToPbkdf2Opts(kdfInfo.Params)
	}

	return nil
}

func mapToScryptOpts(scryptParams map[string]string) heimdall.KeyDerivationOpts {
	n, err := strconv.Atoi(scryptParams["N"])
	if err != nil {
		return nil
	}

	r, err := strconv.Atoi(scryptParams["R"])
	if err != nil {
		return nil
	}

	p, err := strconv.Atoi(scryptParams["P"])
	if err != nil {
		return nil
	}

	return NewScryptOpts(n, r, p)
}

func mapToPbkdf2Opts(pbkdf2Params map[string]string) heimdall.KeyDerivationOpts {
	iteration, err := strconv.Atoi(pbkdf2Params["iteration"])
	if err != nil {
		return nil
	}

	hashOpt, err := strconv.Atoi(pbkdf2Params["hashOpt"])
	if err != nil {
		return nil
	}

	return NewPbkdf2Opts(iteration, hashing.HashOpts(hashOpt))
}
