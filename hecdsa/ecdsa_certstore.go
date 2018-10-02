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

package hecdsa

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/it-chain/heimdall"
)

type CertStorer struct {
}

// StoreCert stores a certificate to certificate store directory.
func (cs *CertStorer) StoreCert(cert *x509.Certificate, certDirPath string) error {
	certPEMBlock := heimdall.X509CertToPem(cert)

	certFilePath, err := makeCertFilePath(certDirPath, cert)
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
func makeCertFilePath(certDirPath string, cert *x509.Certificate) (certFilePath string, err error) {
	if _, err := os.Stat(certDirPath); os.IsNotExist(err) {
		err = os.MkdirAll(certDirPath, 0755)
		if err != nil {
			return "", err
		}
	}

	pub := NewPubKey(cert.PublicKey.(*ecdsa.PublicKey))
	keyId := pub.ID()
	certFilePath = filepath.Join(certDirPath, keyId+".crt")

	return certFilePath, nil
}

type CertLoader struct {
}

// LoadCert loads a certificate by entered key ID.
func (cl *CertLoader) LoadCert(keyId heimdall.KeyID, certDirPath string) (cert *x509.Certificate, err error) {
	certFilePath, err := findCertFileByKeyId(certDirPath, keyId)
	if err != nil {
		return nil, err
	}

	certPEMBlock, err := readCertFile(certFilePath)
	if err != nil {
		return nil, err
	}

	cert, err = heimdall.PemToX509Cert(certPEMBlock)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// findCertFileByKeyId finds a certificate file path by entered key ID.
func findCertFileByKeyId(certDirPath, keyId string) (certFilePath string, err error) {
	files, err := ioutil.ReadDir(certDirPath)
	if err != nil {
		return "", errors.New("invalid cert directory path - failed to read directory path")
	}

	for _, file := range files {
		if strings.Contains(file.Name(), keyId) {
			certFilePath = filepath.Join(certDirPath, file.Name())
			break
		}
	}

	return certFilePath, nil
}

// readCertFile reads certificate file and returns pem bytes of the certificate.
func readCertFile(certFilePath string) (certPEMBlock []byte, err error) {
	certPEMBlock, err = ioutil.ReadFile(certFilePath)
	if err != nil {
		return nil, err
	}

	return certPEMBlock, nil
}
