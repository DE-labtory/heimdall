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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/it-chain/heimdall/cert"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/it-chain/heimdall/mocks"
	"github.com/stretchr/testify/assert"
)

func setUpSigner(t *testing.T) (hecdsa.Signer, *hecdsa.PriKey, *hecdsa.SignerOpts) {
	ecdsaSigner := hecdsa.Signer{}

	pri, err := hecdsa.GenerateKey(hecdsa.ECP384)
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
	rootCert, _ := cert.DERToX509Cert(derBytes)

	// when
	valid, NoErr := ecdsaVerifier.VerifyWithCert(rootCert, signature, message, signerOpt)

	// then
	assert.NoError(t, NoErr)
	assert.True(t, valid)
}
