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

// This file provides ECDSA curve options and functions for using curves comfortable.

package hecdsa

import (
	"crypto/elliptic"

	"errors"
)

var ErrCurveNotSupported = errors.New("curve not supported")

const (
	ECP224 = "P-224"
	ECP256 = "P-256"
	ECP384 = "P-384"
	ECP521 = "P-521"
)

type KeyGenOpt struct {
	Curve elliptic.Curve
}

func NewKeyGenOpt(strCurve string) (*KeyGenOpt, error) {
	opt := new(KeyGenOpt)
	return opt, opt.initKeyGenOpt(strCurve)
}

func (opt *KeyGenOpt) initKeyGenOpt(strCurve string) error {
	switch strCurve {
	case "P-224":
		opt.Curve = elliptic.P224()
	case "P-256":
		opt.Curve = elliptic.P256()
	case "P-384":
		opt.Curve = elliptic.P384()
	case "P-521":
		opt.Curve = elliptic.P521()
	default:
		return ErrCurveNotSupported
	}

	return nil
}

func (opt *KeyGenOpt) ToString() string {
	return opt.Curve.Params().Name
}

func (opt *KeyGenOpt) KeySize() int {
	return opt.Curve.Params().BitSize
}
