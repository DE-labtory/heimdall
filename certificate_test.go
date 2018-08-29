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

package heimdall_test

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"crypto/x509"
	"crypto/rand"
	"os"
	"net/http/httptest"
	"net/http"
	"crypto/x509/pkix"
	"math/big"
	"time"
	"io"
	"github.com/it-chain/heimdall"
)


func TestNewCertStore(t *testing.T) {
	certStore, err := heimdall.NewCertStore(heimdall.TestCertDir)
	assert.NoError(t, err)
	assert.NotNil(t, certStore)
}

func TestCertStore_StoreCert(t *testing.T) {
	certStore, _ := heimdall.NewCertStore(heimdall.TestCertDir)
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	derBytes, err := x509.CreateCertificate(rand.Reader, &heimdall.TestRootCertTemplate, &heimdall.TestRootCertTemplate, &pri.PublicKey, pri)
	assert.NoError(t, err)

	cert, _ := heimdall.DERToX509Cert(derBytes)

	err = certStore.StoreCert(cert)
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestCertDir)
}

func TestCertStore_LoadCert(t *testing.T) {
	certStore, _ := heimdall.NewCertStore(heimdall.TestCertDir)
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	heimdall.TestRootCertTemplate.SubjectKeyId = heimdall.SKIFromPubKey(&pri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &heimdall.TestRootCertTemplate, &heimdall.TestRootCertTemplate, &pri.PublicKey, pri)
	assert.NoError(t, err)

	cert, _ := heimdall.DERToX509Cert(derBytes)

	err = certStore.StoreCert(cert)

	certStore, _ = heimdall.NewCertStore(heimdall.TestCertDir)
	testCert, err := certStore.LoadCert(heimdall.PubKeyToKeyID(&pri.PublicKey))
	assert.NoError(t, err)
	assert.NotNil(t, testCert)

	defer os.RemoveAll(heimdall.TestCertDir)
}

func TestPemToX509Cert(t *testing.T) {
	pri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)
	heimdall.TestRootCertTemplate.SubjectKeyId = heimdall.SKIFromPubKey(&pri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &heimdall.TestRootCertTemplate, &heimdall.TestRootCertTemplate, &pri.PublicKey, pri)
	assert.NoError(t, err)
	pemBytes := heimdall.DERCertToPem(derBytes)

	cert, err := heimdall.PemToX509Cert(pemBytes)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestX509CertToPem(t *testing.T) {
	cert, _ := heimdall.PemToX509Cert([]byte(heimdall.TestCertPemBytes))
	pemBytes := heimdall.X509CertToPem(cert)
	assert.Equal(t, pemBytes, []byte(heimdall.TestCertPemBytes))
}

func TestDERCertToPem(t *testing.T) {
	cert, _ := heimdall.PemToX509Cert([]byte(heimdall.TestCertPemBytes))
	pemBytes := heimdall.DERCertToPem(cert.Raw)
	assert.Equal(t, pemBytes, []byte(heimdall.TestCertPemBytes))
}

func TestX509CertToDER(t *testing.T) {
	cert, _ := heimdall.PemToX509Cert([]byte(heimdall.TestCertPemBytes))
	derBytes := heimdall.X509CertToDER(cert)
	assert.NotNil(t, derBytes)
	assert.Equal(t, []byte(heimdall.TestCertPemBytes), heimdall.DERCertToPem(derBytes))
}

func TestDERToX509Cert(t *testing.T) {
	cert, _ := heimdall.PemToX509Cert([]byte(heimdall.TestCertPemBytes))
	assert.NotNil(t, cert)
	assert.Equal(t, []byte(heimdall.TestCertPemBytes), heimdall.X509CertToPem(cert))
}

func TestCertStore_VerifyCertChain(t *testing.T) {
	certStore, _ := heimdall.NewCertStore(heimdall.TestCertDir)

	// root cert
	rootPri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)

	heimdall.TestRootCertTemplate.SubjectKeyId = heimdall.SKIFromPubKey(&rootPri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &heimdall.TestRootCertTemplate, &heimdall.TestRootCertTemplate, &rootPri.PublicKey, rootPri)
	assert.NoError(t, err)
	rootCert, _ := heimdall.DERToX509Cert(derBytes)

	err = certStore.StoreCert(rootCert)
	assert.NoError(t, err)

	// intermediate cert
	interPri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)

	heimdall.TestIntermediateCertTemplate.SubjectKeyId = heimdall.SKIFromPubKey(&interPri.PublicKey)
	derBytes, err = x509.CreateCertificate(rand.Reader, &heimdall.TestIntermediateCertTemplate, &heimdall.TestRootCertTemplate, &interPri.PublicKey, rootPri)
	assert.NoError(t, err)
	interCert, _ := heimdall.DERToX509Cert(derBytes)

	err = certStore.StoreCert(interCert)
	assert.NoError(t, err)

	// client cert
	ClientPri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)

	heimdall.TestCertTemplate.SubjectKeyId = heimdall.SKIFromPubKey(&ClientPri.PublicKey)
	derBytes, err = x509.CreateCertificate(rand.Reader, &heimdall.TestCertTemplate, &heimdall.TestIntermediateCertTemplate, &ClientPri.PublicKey, interPri)
	assert.NoError(t, err)
	clientCert, _ := heimdall.DERToX509Cert(derBytes)

	err = certStore.StoreCert(clientCert)
	assert.NoError(t, err)

	// verify certificate chain
	err = certStore.VerifyCertChain(clientCert)
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestCertDir)
}

func TestVerifyCert(t *testing.T) {
	// test expired cert
	expiredCert, _ := heimdall.PemToX509Cert([]byte(heimdall.ExpiredCertForTest))
	timeValid, notRevoked, err := heimdall.VerifyCert(expiredCert)
	assert.False(t, timeValid)
	assert.NoError(t, err)
	assert.NotNil(t, notRevoked)

	// test revoked cert
	revokedCert, _ := heimdall.PemToX509Cert([]byte(heimdall.RevokedCertForTest))

	// test normal client cert
	clientCert, _ := heimdall.PemToX509Cert([]byte(heimdall.ClientCertForTest))

	// root cert
	rootPri, _ := heimdall.GenerateKey(heimdall.TestCurveOpt)

	heimdall.TestRootCertTemplate.SubjectKeyId = heimdall.SKIFromPubKey(&rootPri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &heimdall.TestRootCertTemplate, &heimdall.TestRootCertTemplate, &rootPri.PublicKey, rootPri)
	assert.NoError(t, err)
	rootCert, _ := heimdall.DERToX509Cert(derBytes)

	// revoked certificate
	revokedCertificate := new(pkix.RevokedCertificate)
	revokedCertificate.SerialNumber = big.NewInt(44)
	revokedCertificate.RevocationTime = time.Now()
	revokedCertificate.Extensions = nil

	revokedCertList := []pkix.RevokedCertificate{*revokedCertificate}

	// create CRL
	crlBytes, err := rootCert.CreateCRL(rand.Reader, rootPri, revokedCertList, time.Now(), time.Now().Add(time.Hour * 24))
	assert.NoError(t, err)
	assert.NotNil(t, crlBytes)

	// test with httptest server
	testCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, string(crlBytes))
	}))

	revokedCert.CRLDistributionPoints = []string{testCA.URL}

	timeValid, notRevoked, err = heimdall.VerifyCert(revokedCert)
	assert.True(t, timeValid)
	assert.NoError(t, err)
	assert.False(t, notRevoked)

	clientCert.CRLDistributionPoints = []string{testCA.URL}

	timeValid, notRevoked, err = heimdall.VerifyCert(clientCert)
	assert.True(t, timeValid)
	assert.NoError(t, err)
	assert.True(t, notRevoked)
}