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
	"testing"

	"github.com/DE-labtory/heimdall/cert"
	"github.com/DE-labtory/heimdall/hecdsa"
	"github.com/DE-labtory/heimdall/mocks"
	"github.com/stretchr/testify/assert"
)

func TestPemToX509Cert(t *testing.T) {
	// given
	pri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)
	pub := &pri.PublicKey
	hPubKey := hecdsa.NewPubKey(pub)

	mocks.TestRootCertTemplate.SubjectKeyId = hPubKey.SKI()
	derBytes, err := x509.CreateCertificate(rand.Reader, &mocks.TestRootCertTemplate, &mocks.TestRootCertTemplate, pub, pri)
	assert.NoError(t, err)
	pemBytes := cert.DERCertToPem(derBytes)

	// when
	testCert, err := cert.PemToX509Cert(pemBytes)
	nilCert, nilBlockErr := cert.PemToX509Cert([]byte(""))

	// then
	assert.NoError(t, err)
	assert.NotNil(t, testCert)
	assert.Nil(t, nilCert)
	assert.Error(t, nilBlockErr)
}

func TestX509CertToPem(t *testing.T) {
	// given
	testCert, _ := cert.PemToX509Cert([]byte(mocks.TestCertPemBytes))

	// when
	pemBytes := cert.X509CertToPem(testCert)

	// then
	assert.Equal(t, pemBytes, []byte(mocks.TestCertPemBytes))
}

func TestDERCertToPem(t *testing.T) {
	// given
	testCert, _ := cert.PemToX509Cert([]byte(mocks.TestCertPemBytes))

	// when
	pemBytes := cert.DERCertToPem(testCert.Raw)

	// then
	assert.Equal(t, pemBytes, []byte(mocks.TestCertPemBytes))
}

func TestX509CertToDER(t *testing.T) {
	// given
	testCert, _ := cert.PemToX509Cert([]byte(mocks.TestCertPemBytes))

	// when
	derBytes := cert.X509CertToDER(testCert)

	// then
	assert.NotNil(t, derBytes)
	assert.Equal(t, []byte(mocks.TestCertPemBytes), cert.DERCertToPem(derBytes))
}

func TestDERToX509Cert(t *testing.T) {
	// given
	testCert, _ := cert.PemToX509Cert([]byte(mocks.TestCertPemBytes))
	derBytes := cert.X509CertToDER(testCert)

	// when
	recoveredCert, err := cert.DERToX509Cert(derBytes)

	// then
	assert.NoError(t, err)
	assert.Equal(t, testCert, recoveredCert)
}
