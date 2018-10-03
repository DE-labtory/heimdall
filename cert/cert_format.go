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

package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// PemToX509Cert converts PEM formatted certificate to x.509 certificate format.
func PemToX509Cert(certPEMBlock []byte) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode(certPEMBlock)
	if block == nil {
		return nil, errors.New("failed to decode PEM block ")
	}

	cert, err = DERToX509Cert(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// X509CertToPem converts x.509 certificate format to PEM format.
func X509CertToPem(cert *x509.Certificate) []byte {
	return DERCertToPem(cert.Raw)
}

// DERCertToPem converts DER formatted certificate to PEM format.
func DERCertToPem(derBytes []byte) []byte {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	return pemBytes
}

// X509CertToDER converts x.509 certificate to DER format.
func X509CertToDER(cert *x509.Certificate) []byte {
	return cert.Raw
}

// DERToX509Cert converts DER formatted certificate to x.509 certificate.
func DERToX509Cert(derBytes []byte) (cert *x509.Certificate, err error) {
	return x509.ParseCertificate(derBytes)
}
