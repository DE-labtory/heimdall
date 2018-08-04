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
)


func TestNewCertStore(t *testing.T) {
	certStore, err := NewCertStore(TestCertDir)
	assert.NoError(t, err)
	assert.NotNil(t, certStore)
}

func TestCertStore_StoreCert(t *testing.T) {
	certStore, _ := NewCertStore(TestCertDir)
	pri, _ := GenerateKey(TestCurveOpt)
	derBytes, err := x509.CreateCertificate(rand.Reader, &TestRootCertTemplate, &TestRootCertTemplate, &pri.PublicKey, pri)
	assert.NoError(t, err)

	cert, _ := DERToX509Cert(derBytes)

	err = certStore.StoreCert(cert)
	assert.NoError(t, err)

	defer os.RemoveAll(TestCertDir)
}

func TestCertStore_LoadCert(t *testing.T) {
	certStore, _ := NewCertStore(TestCertDir)
	pri, _ := GenerateKey(TestCurveOpt)
	TestRootCertTemplate.SubjectKeyId = SKIFromPubKey(&pri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &TestRootCertTemplate, &TestRootCertTemplate, &pri.PublicKey, pri)
	assert.NoError(t, err)

	cert, _ := DERToX509Cert(derBytes)

	err = certStore.StoreCert(cert)

	certStore, _ = NewCertStore(TestCertDir)
	testCert, err := certStore.LoadCert(PubKeyToKeyID(&pri.PublicKey))
	assert.NoError(t, err)
	assert.NotNil(t, testCert)

	defer os.RemoveAll(TestCertDir)
}

func TestPemToX509Cert(t *testing.T) {
	pri, _ := GenerateKey(TestCurveOpt)
	TestRootCertTemplate.SubjectKeyId = SKIFromPubKey(&pri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &TestRootCertTemplate, &TestRootCertTemplate, &pri.PublicKey, pri)
	assert.NoError(t, err)
	pemBytes := DERCertToPem(derBytes)

	cert, err := PemToX509Cert(pemBytes)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestX509CertToPem(t *testing.T) {
	cert, _ := PemToX509Cert([]byte(TestCertPemBytes))
	pemBytes := X509CertToPem(cert)
	assert.Equal(t, pemBytes, []byte(TestCertPemBytes))
}

func TestDERCertToPem(t *testing.T) {
	cert, _ := PemToX509Cert([]byte(TestCertPemBytes))
	pemBytes := DERCertToPem(cert.Raw)
	assert.Equal(t, pemBytes, []byte(TestCertPemBytes))
}

func TestX509CertToDER(t *testing.T) {
	cert, _ := PemToX509Cert([]byte(TestCertPemBytes))
	derBytes := X509CertToDER(cert)
	assert.NotNil(t, derBytes)
	assert.Equal(t, []byte(TestCertPemBytes), DERCertToPem(derBytes))
}

func TestDERToX509Cert(t *testing.T) {
	cert, _ := PemToX509Cert([]byte(TestCertPemBytes))
	assert.NotNil(t, cert)
	assert.Equal(t, []byte(TestCertPemBytes), X509CertToPem(cert))
}

func TestCertStore_VerifyCertChain(t *testing.T) {
	certStore, _ := NewCertStore(TestCertDir)

	// root cert
	rootPri, _ := GenerateKey(TestCurveOpt)

	TestRootCertTemplate.SubjectKeyId = SKIFromPubKey(&rootPri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &TestRootCertTemplate, &TestRootCertTemplate, &rootPri.PublicKey, rootPri)
	assert.NoError(t, err)
	rootCert, _ := DERToX509Cert(derBytes)

	err = certStore.StoreCert(rootCert)
	assert.NoError(t, err)

	// intermediate cert
	interPri, _ := GenerateKey(TestCurveOpt)

	TestIntermediateCertTemplate.SubjectKeyId = SKIFromPubKey(&interPri.PublicKey)
	derBytes, err = x509.CreateCertificate(rand.Reader, &TestIntermediateCertTemplate, &TestRootCertTemplate, &interPri.PublicKey, rootPri)
	assert.NoError(t, err)
	interCert, _ := DERToX509Cert(derBytes)

	err = certStore.StoreCert(interCert)
	assert.NoError(t, err)

	// client cert
	ClientPri, _ := GenerateKey(TestCurveOpt)

	TestCertTemplate.SubjectKeyId = SKIFromPubKey(&ClientPri.PublicKey)
	derBytes, err = x509.CreateCertificate(rand.Reader, &TestCertTemplate, &TestIntermediateCertTemplate, &ClientPri.PublicKey, interPri)
	assert.NoError(t, err)
	clientCert, _ := DERToX509Cert(derBytes)

	err = certStore.StoreCert(clientCert)
	assert.NoError(t, err)

	// verify certificate chain
	err = certStore.VerifyCertChain(clientCert)
	assert.NoError(t, err)

	defer os.RemoveAll(TestCertDir)
}

func TestVerifyCert(t *testing.T) {
	// test expired cert
	expiredCert, _ := PemToX509Cert([]byte(ExpiredCertForTest))
	timeValid, notRevoked, err := VerifyCert(expiredCert)
	assert.False(t, timeValid)
	assert.NoError(t, err)
	assert.NotNil(t, notRevoked)

	// test revoked cert
	revokedCert, _ := PemToX509Cert([]byte(RevokedCertForTest))

	// root cert
	rootPri, _ := GenerateKey(TestCurveOpt)

	TestRootCertTemplate.SubjectKeyId = SKIFromPubKey(&rootPri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &TestRootCertTemplate, &TestRootCertTemplate, &rootPri.PublicKey, rootPri)
	assert.NoError(t, err)
	rootCert, _ := DERToX509Cert(derBytes)

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

	timeValid, notRevoked, err = VerifyCert(revokedCert)
	assert.True(t, timeValid)
	assert.NoError(t, err)
	assert.False(t, notRevoked)
}