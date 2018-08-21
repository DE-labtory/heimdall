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

package heimdall

import (
	"crypto/x509"
	"os"
	"io/ioutil"
	"path/filepath"
	"errors"
	"strings"
	"encoding/pem"
	"crypto/ecdsa"
	"bytes"
	"time"
	"crypto/x509/pkix"
	"net/http"
)

type CertStore struct{
	certDirPath string
}

// NewCertStore makes new certificate store.
func NewCertStore(certDirPath string) (cs *CertStore, err error) {
	cs = new(CertStore)
	return cs, cs.initCertStore(certDirPath)
}

// initCertStore initiates a certificate store.
func (cs *CertStore) initCertStore(certDirPath string) error {
	if len(certDirPath) == 0 {
		return errors.New("invalid certificate directory path - entered path is empty string")
	}
	cs.certDirPath = certDirPath

	return nil
}

// StoreCert stores a certificate to certificate store directory.
func (cs *CertStore) StoreCert(cert *x509.Certificate) error {
	certPEMBlock := X509CertToPem(cert)

	certFilePath, err := cs.makeCertFilePath(cert)
	if err != nil {
		return err
	}

	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		err = ioutil.WriteFile(certFilePath, certPEMBlock, 0700)
		if err != nil {
			return err
		}
	}

	return nil
}

// makeCertFilePath makes certificate file path for a certificate by its key ID.
func (cs *CertStore) makeCertFilePath(cert *x509.Certificate) (certFilePath string, err error) {
	if _, err := os.Stat(cs.certDirPath); os.IsNotExist(err) {
		err = os.MkdirAll(cs.certDirPath, 0755)
		if err != nil {
			return "", err
		}
	}

	keyId := PubKeyToKeyID(cert.PublicKey.(*ecdsa.PublicKey))
	certFilePath = filepath.Join(cs.certDirPath, keyId + ".crt")

	return certFilePath, nil
}

// LoadCert loads a certificate by entered key ID.
func (cs *CertStore) LoadCert(keyId string) (cert *x509.Certificate, err error) {
	certFilePath, err := cs.findCertFileByKeyId(keyId)
	if err != nil {
		return nil, err
	}

	certPEMBlock, err := cs.readCertFile(certFilePath)
	if err != nil {
		return nil, err
	}

	cert, err = PemToX509Cert(certPEMBlock)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// findCertFileByKeyId finds a certificate file path by entered key ID.
func (cs *CertStore) findCertFileByKeyId(keyId string) (certFilePath string, err error) {
	files, err := ioutil.ReadDir(cs.certDirPath)
	if err != nil {
		return "", errors.New("invalid cert directory path - failed to read directory path")
	}

	for _, file := range files {
		if strings.Contains(file.Name(), keyId) {
			certFilePath = filepath.Join(cs.certDirPath, file.Name())
			break
		}
	}

	return certFilePath, nil
}

// readCertFile reads certificate file and returns pem bytes of the certificate.
func (cs *CertStore) readCertFile(certFilePath string) (certPEMBlock []byte, err error) {
	certPEMBlock, err = ioutil.ReadFile(certFilePath)
	if err != nil {
		return nil, err
	}

	return certPEMBlock, nil
}

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
		Type: "CERTIFICATE",
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

// VerifyCertChain verifies a certificate from local certificates in certificate store directory.
func (cs *CertStore) VerifyCertChain(cert *x509.Certificate) error {
	roots, err := cs.makeRootsPool()
	if err != nil {
		return err
	}

	intermediates, err := cs.makeIntermediatesPool()
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots: roots,
		Intermediates:intermediates,
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}

// makeRootsPool makes certificate pool of root certificates in certificate store directory.
func (cs *CertStore) makeRootsPool() (rootsPool *x509.CertPool, err error) {
	rootsPool = x509.NewCertPool()

	files, err := ioutil.ReadDir(cs.certDirPath)
	if err != nil {
		return nil, errors.New("invalid cert directory path - failed to read directory path")
	}

	for _, file := range files {
		certFilePath := filepath.Join(cs.certDirPath, file.Name())
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
		return nil, errors.New("no root certificate in certificate store directory")
	}

	return rootsPool, nil
}

// makeIntermediatesPool makes certificate pool of intermediate certificates in certificate store directory.
func (cs *CertStore) makeIntermediatesPool() (intermediatesPool *x509.CertPool, err error) {
	intermediatesPool = x509.NewCertPool()

	files, err := ioutil.ReadDir(cs.certDirPath)
	if err != nil {
		return nil, errors.New("invalid cert directory path - failed to read directory path")
	}

	for _, file := range files {
		certFilePath := filepath.Join(cs.certDirPath, file.Name())
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
// if returned values are false true nil, then certificate is expired.
// if returned values are true false nil, then certificate is revoked.
func VerifyCert(cert *x509.Certificate) (timeValid bool, notRevoked bool, err error) {
	// check if expired or invalid generation time
	timeValid, err = checkTime(cert.NotBefore, cert.NotAfter)
	if err != nil {
		return timeValid, notRevoked, err
	}

	if timeValid != true {
		return timeValid, notRevoked, nil
	}

	// check if revoked
	for _, url := range cert.CRLDistributionPoints {
		crl, err := requestCRL(url)
		if err != nil {
			return timeValid, notRevoked, err
		}

		if checkRevocation(cert, crl) != true {
			return timeValid, notRevoked,nil
		}
	}

	return timeValid, notRevoked, nil
}

// checkTime checks if entered certificate's generated/expired time is valid.
func checkTime(notBefore time.Time, notAfter time.Time) (bool, error) {
	if time.Now().Before(notBefore) {
		return false, errors.New("invalid certificate - certificate's generated time is invalid")
	}

	if time.Now().After(notAfter) {
		return false, nil
	}

	return true, nil
}

// requestCRL requests CRL(Certificate Revocation List) from CRLDistributionURL.
func requestCRL(url string) (*pkix.CertificateList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL")
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCRL(body)
}

// checkRevocation checks if entered certificate is revoked by CRL(Certificate Revocation List).
func checkRevocation(cert *x509.Certificate, crl *pkix.CertificateList) bool {
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return false
		}
	}

	return true
}