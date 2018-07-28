// This file provides key generation options.

package heimdall

import (
	"crypto/elliptic"
	"strings"
)

// CurveOpts represents curve options by integer.
type CurveOpts int

// Curve name -> secpXXXr1 = NIST P-XXX
const (
	SECP224R1 CurveOpts = iota
	SECP256R1
	SECP384R1
	SECP521R1

	UNKNOWN
)

var curveArr = [...]string {
	"secp224r1",
	"secp256r1",
	"secp384r1",
	"secp521r1",

	"unknown",
}

// KeySize returns the curve's field size.
func (opt CurveOpts) KeySize() string {
	keySize := strings.Trim(opt.String(), "secp r1")
	return keySize
}

// ValidCheck checks the input key generation option is valid or not.
func (opt CurveOpts) ValidCheck() bool {

	if opt < 0 || opt >= CurveOpts(len(curveArr)) {
		return false
	}

	return true

}

// String coverts format of key generation option from KeyGenOpts to string.
func (opt CurveOpts) String() string {
	if !opt.ValidCheck() {
		return "unknown"
	}

	return curveArr[opt]
}

// CurveOptToCurve get curve corresponding to curve option.
func (opt CurveOpts) CurveOptToCurve() elliptic.Curve {

	switch opt {
	case SECP224R1:
		return elliptic.P224()
	case SECP256R1:
		return elliptic.P256()
	case SECP384R1:
		return elliptic.P384()
	case SECP521R1:
		return elliptic.P521()
	default:
		return nil
	}

}

// StringToKeyGenOpts converts format of key generation option from string to KeyGenOpts
func StringToCurveOpt(rawOpts string) CurveOpts {
	for idx, opts := range curveArr {
		if rawOpts == opts {
			return CurveOpts(idx)
		}
	}

	return UNKNOWN
}

// ECDSACurveToKeyGenOpts converts format of ECDSA elliptic curve from elliptic.Curve to KeyGenOpts.
func CurveToCurveOpt(curve elliptic.Curve) CurveOpts {

	switch curve {
	case elliptic.P224():
		return SECP224R1
	case elliptic.P256():
		return SECP256R1
	case elliptic.P384():
		return SECP384R1
	case elliptic.P521():
		return SECP521R1
	default:
		return UNKNOWN
	}

}