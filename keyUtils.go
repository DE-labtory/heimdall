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

// This file provides supporting function for key format and type.

package heimdall

import (
	"crypto/x509"
	"errors"
)

//// PEMToPublicKey converts PEM to public key format.
//func PEMToPublicKey(data []byte, curveOpt heimdall.CurveOpts) (heimdall.PubKey, error) {
//
//	if len(data) == 0 {
//		return nil, errors.New("input data should not be NIL")
//	}
//
//	block, _ := pem.Decode(data)
//	if block == nil {
//		return nil, errors.New("failed to decode data")
//	}
//
//	key, err := DERToPublicKey(block.Bytes)
//	if err != nil {
//		return nil, errors.New("failed to convert PEM data to public key")
//	}
//
//	pub, err := MatchPublicKeyOpt(key, curveOpt)
//	if err != nil {
//		return nil, errors.New("failed to convert the key type to matched public key")
//	}
//
//	return pub, nil
//
//}

//// PEMToPrivateKey converts PEM to private key format.
//func PEMToPrivateKey(data []byte, curveOpt heimdall.CurveOpts) (heimdall.PriKey, error) {
//	if len(data) == 0 {
//		return nil, errors.New("input data should not be NIL")
//	}
//
//	block, _ := pem.Decode(data)
//	if block == nil {
//		return nil, errors.New("failed to decode data")
//	}
//
//	key, err := DERToPrivateKey(block.Bytes)
//	if err != nil {
//		return nil, errors.New("failed to convert PEM data to private key")
//	}
//
//	pri, err := MatchPrivateKeyOpt(key, curveOpt)
//	if err != nil {
//		return nil, errors.New("failed to convert the key type to matched private key")
//	}
//
//	return pri, nil
//
//}

// DERToPublicKey converts DER to public key format.
func DERToPublicKey(data []byte) (interface{}, error) {

	if len(data) == 0 {
		return nil, errors.New("input data should not be NIL")
	}

	key, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, errors.New("failed to Parse data")
	}

	return key, nil

}

// DERToPrivateKey converts DER to private key format.
func DERToPrivateKey(data []byte) (interface{}, error) {

	var key interface{}
	var err error

	if len(data) == 0 {
		return nil, errors.New("input data should not be NIL")
	}

	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, err
	}

	if key, err = x509.ParseECPrivateKey(data); err == nil {
		return key, err
	}

	return nil, errors.New("unspported Private Key Type")

}

