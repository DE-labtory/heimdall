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
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"
	"time"
)

var ErrCertGenTimeIsFuture = errors.New("invalid certificate - certificate's generated time is not past time")
var ErrCertExpired = errors.New("invalid certificate - certificate is expired")
var ErrCertRevoked = errors.New("invalid certificate - revoked certificate")
var ErrNoRootCertInPath = errors.New("no root certificate in certificate directory path")

// VerifyCertChain verifies a certificate from local certificates in certificate store directory.
func VerifyChain(cert *x509.Certificate, certDirPath string) error {
	roots, err := makeRootsPool(certDirPath)
	if err != nil {
		return err
	}

	intermediates, err := makeIntermediatesPool(certDirPath)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}

// makeRootsPool makes certificate pool of root certificates in certificate store directory.
func makeRootsPool(certDirPath string) (rootsPool *x509.CertPool, err error) {
	rootsPool = x509.NewCertPool()

	files, err := ioutil.ReadDir(certDirPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		certFilePath := filepath.Join(certDirPath, file.Name())
		certPEMBlock, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			return nil, err
		}

		cert, err := PemToX509Cert(certPEMBlock)
		if cert.IsCA == true && bytes.Compare(cert.RawIssuer, cert.RawSubject) == 0 {
			rootsPool.AddCert(cert)
		}
	}

	if len(rootsPool.Subjects()) == 0 {
		return nil, ErrNoRootCertInPath
	}

	return rootsPool, nil
}

// makeIntermediatesPool makes certificate pool of intermediate certificates in certificate store directory.
func makeIntermediatesPool(certDirPath string) (intermediatesPool *x509.CertPool, err error) {
	intermediatesPool = x509.NewCertPool()

	files, err := ioutil.ReadDir(certDirPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		certFilePath := filepath.Join(certDirPath, file.Name())
		certPEMBlock, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			return nil, err
		}

		cert, err := PemToX509Cert(certPEMBlock)
		if cert.IsCA == true && bytes.Compare(cert.RawIssuer, cert.RawSubject) != 0 {
			intermediatesPool.AddCert(cert)
		}
	}

	return intermediatesPool, nil
}

// VerifyCert verifies a certificate's validity.
func Verify(cert *x509.Certificate) error {
	// check if expired or invalid generation time
	err := checkTime(cert.NotBefore, cert.NotAfter)
	if err != nil {
		return err
	}

	// check if revoked
	for _, url := range cert.CRLDistributionPoints {
		crl, err := requestCRL(url)
		if err != nil {
			return err
		}

		err = checkRevocation(cert, crl)
		if err != nil {
			return err
		}
	}

	return nil
}

// checkTime checks if entered certificate's generated/expired time is valid.
func checkTime(notBefore time.Time, notAfter time.Time) error {
	if time.Now().Before(notBefore) {
		return ErrCertGenTimeIsFuture
	}

	if time.Now().After(notAfter) {
		return ErrCertExpired
	}

	return nil
}

// requestCRL requests CRL(Certificate Revocation List) from CRLDistributionURL.
func requestCRL(url string) (*pkix.CertificateList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL - http status code :[" + strconv.Itoa(resp.StatusCode) + "]")
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCRL(body)
}

// checkRevocation checks if entered certificate is revoked by CRL(Certificate Revocation List).
func checkRevocation(cert *x509.Certificate, crl *pkix.CertificateList) error {
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return ErrCertRevoked
		}
	}

	return nil
}
