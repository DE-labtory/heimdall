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

	"regexp"
	"strconv"
)

// KeyGenOpts represents ECDSA key generation options by integer.
type KeyGenOpts int

// Curve name -> secpXXXr1 = NIST P-XXX
const (
	ECP224 KeyGenOpts = iota
	ECP256
	ECP384
	ECP521
	invalidECDSAOpt
)

var curves = [...]string{
	"P-224",
	"P-256",
	"P-384",
	"P-521",
	"invalid ECDSA key generation option",
}

// ToString obtains curve's name as string format from ECDSAKeyGen option type.
func (opt KeyGenOpts) ToString() string {
	return curves[opt]
}

// ValidCheck checks the curve option is valid or not.
func (opt KeyGenOpts) IsValid() bool {
	return opt >= 0 && opt < invalidECDSAOpt
}

// GetKeySize returns the curve's field size.
func (opt KeyGenOpts) KeySize() int {
	re := regexp.MustCompile("[0-9]{3,4}")
	keySize, err := strconv.Atoi(re.FindString(opt.ToString()))
	if err != nil {
		return -1
	}

	return keySize
}

// ToCurve get elliptic curve corresponding to curve option.
func (opt KeyGenOpts) ToCurve() elliptic.Curve {
	switch opt {
	case ECP224:
		return elliptic.P224()
	case ECP256:
		return elliptic.P256()
	case ECP384:
		return elliptic.P384()
	case ECP521:
		return elliptic.P521()
	default:
		return nil
	}
}

// StringToKeyGenOpt obtains ECDSA key generation option from string (curve name).
func StringToKeyGenOpt(strFormatOpt string) KeyGenOpts {
	for idx, opts := range curves {
		if strFormatOpt == opts {
			return KeyGenOpts(idx)
		}
	}

	return invalidECDSAOpt
}

// CurveToCurveOpt obtains ECDSA key generation option from elliptic.Curve type.
func CurveToKeyGenOpt(curve elliptic.Curve) KeyGenOpts {
	switch curve {
	case elliptic.P224():
		return ECP224
	case elliptic.P256():
		return ECP256
	case elliptic.P384():
		return ECP384
	case elliptic.P521():
		return ECP521
	}

	return invalidECDSAOpt
}
