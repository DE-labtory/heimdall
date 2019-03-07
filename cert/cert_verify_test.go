/*
 * Copyright 2018 DE-labtory
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

package cert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DE-labtory/heimdall"
	"github.com/DE-labtory/heimdall/cert"
	"github.com/DE-labtory/heimdall/hecdsa"
	"github.com/DE-labtory/heimdall/mocks"
	"github.com/stretchr/testify/assert"
)

func TestVerifyChain(t *testing.T) {
	// given
	//root cert
	rootPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootPub := &rootPri.PublicKey
	assert.NoError(t, err)
	hRootPri := hecdsa.NewPriKey(rootPri)

	mocks.TestRootCertTemplate.SubjectKeyId = hRootPri.SKI()
	derBytes, err := x509.CreateCertificate(rand.Reader, &mocks.TestRootCertTemplate, &mocks.TestRootCertTemplate, rootPub, rootPri)
	assert.NoError(t, err)
	rootCert, _ := cert.DERToX509Cert(derBytes)

	err = cert.Store(rootCert, heimdall.TestCertDir)
	assert.NoError(t, err)

	// intermediate cert
	interPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	interPub := &interPri.PublicKey
	assert.NoError(t, err)
	hInterPri := hecdsa.NewPriKey(interPri)

	mocks.TestIntermediateCertTemplate.SubjectKeyId = hInterPri.SKI()
	derBytes, err = x509.CreateCertificate(rand.Reader, &mocks.TestIntermediateCertTemplate, &mocks.TestRootCertTemplate, interPub, rootPri)
	assert.NoError(t, err)
	interCert, _ := cert.DERToX509Cert(derBytes)

	err = cert.Store(interCert, heimdall.TestCertDir)
	assert.NoError(t, err)

	// client cert
	clientPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	clientPub := &clientPri.PublicKey
	assert.NoError(t, err)
	hClientPri := hecdsa.NewPriKey(clientPri)

	mocks.TestIntermediateCertTemplate.SubjectKeyId = hClientPri.SKI()
	derBytes, err = x509.CreateCertificate(rand.Reader, &mocks.TestCertTemplate, &mocks.TestIntermediateCertTemplate, clientPub, interPri)
	assert.NoError(t, err)
	clientCert, _ := cert.DERToX509Cert(derBytes)

	// when
	err = cert.VerifyChain(clientCert, heimdall.TestCertDir)
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestCertDir)
}

func TestVerify(t *testing.T) {
	// given

	// expired cert
	expiredCert, _ := cert.PemToX509Cert([]byte(mocks.ExpiredCertForTest))
	// revoked cert
	revokedCert, _ := cert.PemToX509Cert([]byte(mocks.RevokedCertForTest))
	// normal client cert
	clientCert, _ := cert.PemToX509Cert([]byte(mocks.ClientCertForTest))

	// root cert
	rootPri, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootPub := &rootPri.PublicKey
	hRootPub := hecdsa.NewPubKey(rootPub)

	mocks.TestRootCertTemplate.SubjectKeyId = hRootPub.SKI()
	derBytes, err := x509.CreateCertificate(rand.Reader, &mocks.TestRootCertTemplate, &mocks.TestRootCertTemplate, rootPub, rootPri)
	assert.NoError(t, err)
	rootCert, _ := cert.DERToX509Cert(derBytes)

	// revoked certificate setting
	revokedCertificate := new(pkix.RevokedCertificate)
	revokedCertificate.SerialNumber = big.NewInt(44)
	revokedCertificate.RevocationTime = time.Now()
	revokedCertificate.Extensions = nil

	revokedCertList := []pkix.RevokedCertificate{*revokedCertificate}

	// create CRL (Certificate Revocation List)
	crlBytes, err := rootCert.CreateCRL(rand.Reader, rootPri, revokedCertList, time.Now(), time.Now().Add(time.Hour*24))
	assert.NoError(t, err)
	assert.NotNil(t, crlBytes)

	// httptest server for testing
	testCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, string(crlBytes))
	}))

	revokedCert.CRLDistributionPoints = []string{testCA.URL}
	clientCert.CRLDistributionPoints = []string{testCA.URL}

	// when
	expiredErr := cert.Verify(expiredCert)
	revokedErr := cert.Verify(revokedCert)
	clientErr := cert.Verify(clientCert)

	// then
	assert.Error(t, expiredErr)
	assert.Error(t, revokedErr)
	assert.NoError(t, clientErr)
}
