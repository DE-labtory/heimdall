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
)

type CertStore struct{
	certDirPath string
}

func NewCertStore(certDirPath string) (cs *CertStore, err error) {
	cs = new(CertStore)
	return cs, cs.initCertStore(certDirPath)
}

func (cs *CertStore) initCertStore(certDirPath string) error {
	if len(certDirPath) == 0 {
		return errors.New("invalid certificate directory path - entered path is empty string")
	}
	cs.certDirPath = certDirPath

	return nil
}

func (cs *CertStore) StoreCert(certPEMBlock []byte) error {
	certFilePath, err := cs.makeCertFilePath(certPEMBlock)
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

func (cs *CertStore) makeCertFilePath(certPEMBlock []byte) (certFilePath string, err error) {
	if _, err := os.Stat(cs.certDirPath); os.IsNotExist(err) {
		err = os.MkdirAll(cs.certDirPath, 0755)
		if err != nil {
			return "", err
		}
	}

	cert, err := cs.pemToX509Cert(certPEMBlock)
	if err != nil {
		return "", err
	}

	keyId := PubKeyToKeyID(cert.PublicKey.(*ecdsa.PublicKey))
	certFilePath = filepath.Join(cs.certDirPath, keyId + ".crt")

	return certFilePath, nil
}

func (cs *CertStore) LoadCert(keyId string) (cert *x509.Certificate, err error) {
	certPEMBlock, err := cs.readCertFile(keyId)
	if err != nil {
		return nil, err
	}

	cert, err = cs.pemToX509Cert(certPEMBlock)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (cs *CertStore) readCertFile(keyId string) (certPEMBlock []byte, err error) {
	var certFilePath string

	files, err := ioutil.ReadDir(cs.certDirPath)
	if err != nil {
		return nil, errors.New("invalid cert directory path - failed to read directory path")
	}

	for _, file := range files {
		if strings.Contains(file.Name(), keyId) {
			certFilePath = filepath.Join(cs.certDirPath, file.Name())
			break
		}
	}

	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		return nil, errors.New("invalid keystore path - not exist")
	}

	certPEMBlock, err = ioutil.ReadFile(certFilePath)
	if err != nil {
		return nil, err
	}

	return certPEMBlock, nil
}

func (cs *CertStore) pemToX509Cert(certPEMBlock []byte) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode(certPEMBlock)
	if block == nil {
		return nil, errors.New("failed to decode PEM block ")
	}

	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}