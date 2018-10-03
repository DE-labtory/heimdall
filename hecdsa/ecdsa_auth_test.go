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

package hecdsa_test

import (
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"os"

	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/it-chain/heimdall/mocks"
	"github.com/stretchr/testify/assert"
)

func setUpSigner(t *testing.T) (hecdsa.Signer, *hecdsa.PriKey, *hecdsa.SignerOpts) {
	ecdsaSigner := hecdsa.Signer{}
	generator := hecdsa.KeyGenerator{}

	pri, err := generator.GenerateKey(hecdsa.ECP384)
	assert.NoError(t, err)

	signerOpt := hecdsa.NewSignerOpts(hashing.SHA384)
	assert.True(t, signerOpt.IsValid())

	return ecdsaSigner, pri.(*hecdsa.PriKey), signerOpt
}

func TestSigner_Sign(t *testing.T) {
	// given
	ecdsaSigner, pri, signerOpt := setUpSigner(t)
	message := []byte("hello")

	// when
	signature, noErr := ecdsaSigner.Sign(pri, message, signerOpt)
	nilSig, err := ecdsaSigner.Sign(pri, nil, signerOpt)

	// then
	assert.NotNil(t, signature)
	assert.NoError(t, noErr)
	assert.Nil(t, nilSig)
	assert.Error(t, err)
}

func TestVerifier_Verify(t *testing.T) {
	// given
	ecdsaSigner, pri, signerOpt := setUpSigner(t)
	otherPri := setUpPriKey(t)
	otherPub := otherPri.PublicKey()

	message := []byte("hello")
	wrongMessage := []byte("this is wrong meesage")

	signature, err := ecdsaSigner.Sign(pri, message, signerOpt)
	assert.NotNil(t, signature)
	assert.NoError(t, err)

	pub := pri.PublicKey()

	ecdsaVerifier := hecdsa.Verifier{}

	// when
	valid, noErr := ecdsaVerifier.Verify(pub, signature, message, signerOpt)
	inValid, _ := ecdsaVerifier.Verify(pub, signature, wrongMessage, signerOpt)
	inValid2, _ := ecdsaVerifier.Verify(otherPub, signature, message, signerOpt)
	_, err = ecdsaVerifier.Verify(pub, []byte("wrong sig"), message, signerOpt)
	_, err2 := ecdsaVerifier.Verify(pub, signature, nil, signerOpt)

	// then
	assert.NoError(t, noErr)
	assert.Error(t, err)
	assert.Error(t, err2)

	assert.True(t, valid)
	assert.False(t, inValid)
	assert.False(t, inValid2)
}

func TestVerifier_VerifyWithCert(t *testing.T) {
	// given
	ecdsaSigner, _, signerOpt := setUpSigner(t)

	message := []byte("hello")

	ecdsaVerifier := hecdsa.Verifier{}

	//root cert
	rootPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootPub := &rootPri.PublicKey
	assert.NoError(t, err)
	hPri := hecdsa.NewPriKey(rootPri)

	signature, err := ecdsaSigner.Sign(hPri, message, signerOpt)
	assert.NotNil(t, signature)
	assert.NoError(t, err)

	mocks.TestRootCertTemplate.SubjectKeyId = hPri.SKI()
	derBytes, err := x509.CreateCertificate(rand.Reader, &mocks.TestRootCertTemplate, &mocks.TestRootCertTemplate, rootPub, rootPri)
	assert.NoError(t, err)
	rootCert, _ := heimdall.DERToX509Cert(derBytes)

	// when
	valid, NoErr := ecdsaVerifier.VerifyWithCert(rootCert, signature, message, signerOpt)

	// then
	assert.NoError(t, NoErr)
	assert.True(t, valid)
}

func TestCertVerifier_VerifyCertChain(t *testing.T) {
	// given
	certVerifier := hecdsa.CertVerifier{}
	certStorer := hecdsa.CertStorer{}

	//root cert
	rootPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootPub := &rootPri.PublicKey
	assert.NoError(t, err)
	hRootPri := hecdsa.NewPriKey(rootPri)

	mocks.TestRootCertTemplate.SubjectKeyId = hRootPri.SKI()
	derBytes, err := x509.CreateCertificate(rand.Reader, &mocks.TestRootCertTemplate, &mocks.TestRootCertTemplate, rootPub, rootPri)
	assert.NoError(t, err)
	rootCert, _ := heimdall.DERToX509Cert(derBytes)

	err = certStorer.StoreCert(rootCert, heimdall.TestCertDir)
	assert.NoError(t, err)

	// intermediate cert
	interPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	interPub := &interPri.PublicKey
	assert.NoError(t, err)
	hInterPri := hecdsa.NewPriKey(interPri)

	mocks.TestIntermediateCertTemplate.SubjectKeyId = hInterPri.SKI()
	derBytes, err = x509.CreateCertificate(rand.Reader, &mocks.TestIntermediateCertTemplate, &mocks.TestRootCertTemplate, interPub, rootPri)
	assert.NoError(t, err)
	interCert, _ := heimdall.DERToX509Cert(derBytes)

	err = certStorer.StoreCert(interCert, heimdall.TestCertDir)
	assert.NoError(t, err)

	// client cert
	clientPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	clientPub := &clientPri.PublicKey
	assert.NoError(t, err)
	hClientPri := hecdsa.NewPriKey(clientPri)

	mocks.TestIntermediateCertTemplate.SubjectKeyId = hClientPri.SKI()
	derBytes, err = x509.CreateCertificate(rand.Reader, &mocks.TestCertTemplate, &mocks.TestIntermediateCertTemplate, clientPub, interPri)
	assert.NoError(t, err)
	clientCert, _ := heimdall.DERToX509Cert(derBytes)

	// when
	err = certVerifier.VerifyCertChain(clientCert, heimdall.TestCertDir)
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestCertDir)
}

func TestCertVerifier_VerifyCert(t *testing.T) {
	// given
	certVerifier := hecdsa.CertVerifier{}

	// expired cert
	expiredCert, _ := heimdall.PemToX509Cert([]byte(mocks.ExpiredCertForTest))
	// revoked cert
	revokedCert, _ := heimdall.PemToX509Cert([]byte(mocks.RevokedCertForTest))
	// normal client cert
	clientCert, _ := heimdall.PemToX509Cert([]byte(mocks.ClientCertForTest))

	// root cert
	rootPri, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootPub := &rootPri.PublicKey
	hRootPub := hecdsa.NewPubKey(rootPub)

	mocks.TestRootCertTemplate.SubjectKeyId = hRootPub.SKI()
	derBytes, err := x509.CreateCertificate(rand.Reader, &mocks.TestRootCertTemplate, &mocks.TestRootCertTemplate, rootPub, rootPri)
	assert.NoError(t, err)
	rootCert, _ := heimdall.DERToX509Cert(derBytes)

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
	expiredErr := certVerifier.VerifyCert(expiredCert)
	revokedErr := certVerifier.VerifyCert(revokedCert)
	clientErr := certVerifier.VerifyCert(clientCert)

	// then
	assert.Error(t, expiredErr)
	assert.Error(t, revokedErr)
	assert.NoError(t, clientErr)
}
