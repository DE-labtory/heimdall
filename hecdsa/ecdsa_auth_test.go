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

	"os"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/cert"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/it-chain/heimdall/mocks"
	"github.com/stretchr/testify/assert"
)

func setUpLocalKey(t *testing.T) (keyDirPath string, tearDown func()) {
	ecdsaKeyGenOpt, err := hecdsa.NewKeyGenOpt(hecdsa.ECP384)
	assert.NoError(t, err)
	pri, err := hecdsa.GenerateKey(ecdsaKeyGenOpt)
	assert.NoError(t, err)

	err = hecdsa.StorePriKeyWithoutPwd(pri, heimdall.TestPriKeyDir)
	assert.NoError(t, err)

	return heimdall.TestPriKeyDir, func() {
		defer os.RemoveAll(heimdall.TestPriKeyDir)
	}
}

func TestSignWithKeyInLocal(t *testing.T) {
	// given
	keyDirPath, tearDown := setUpLocalKey(t)
	defer tearDown()

	hashOpt, err := hashing.NewHashOpt(hashing.SHA384)
	signerOpt := hecdsa.NewSignerOpts(hashOpt)
	assert.NoError(t, err)
	message := []byte("hello world")

	// when
	signature, err := hecdsa.SignWithKeyInLocal(keyDirPath, message, signerOpt)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, signature)
}

func TestVerify(t *testing.T) {
	// given
	pri := setUpPriKey(t)
	hashOpt, err := hashing.NewHashOpt(hashing.SHA384)
	assert.NoError(t, err)
	signerOpt := hecdsa.NewSignerOpts(hashOpt)
	otherPri := setUpPriKey(t)
	otherPub := otherPri.PublicKey()

	message := []byte("hello")
	wrongMessage := []byte("this is wrong meesage")

	signature, err := hecdsa.Sign(pri, message, signerOpt)
	assert.NotNil(t, signature)
	assert.NoError(t, err)

	pub := pri.PublicKey()

	// when
	valid, noErr := hecdsa.Verify(pub, signature, message, signerOpt)
	inValid, _ := hecdsa.Verify(pub, signature, wrongMessage, signerOpt)
	inValid2, _ := hecdsa.Verify(otherPub, signature, message, signerOpt)
	_, err = hecdsa.Verify(pub, []byte("wrong sig"), message, signerOpt)
	_, err2 := hecdsa.Verify(pub, signature, nil, signerOpt)

	// then
	assert.NoError(t, noErr)
	assert.Error(t, err)
	assert.Error(t, err2)

	assert.True(t, valid)
	assert.False(t, inValid)
	assert.False(t, inValid2)
}

func TestVerifyWithCert(t *testing.T) {
	// given
	hashOpt, err := hashing.NewHashOpt(hashing.SHA384)
	assert.NoError(t, err)
	signerOpt := hecdsa.NewSignerOpts(hashOpt)

	message := []byte("hello")

	//root cert
	rootPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootPub := &rootPri.PublicKey
	assert.NoError(t, err)
	hPri := hecdsa.NewPriKey(rootPri)

	signature, err := hecdsa.Sign(hPri, message, signerOpt)
	assert.NotNil(t, signature)
	assert.NoError(t, err)

	mocks.TestRootCertTemplate.SubjectKeyId = hPri.SKI()
	derBytes, err := x509.CreateCertificate(rand.Reader, &mocks.TestRootCertTemplate, &mocks.TestRootCertTemplate, rootPub, rootPri)
	assert.NoError(t, err)
	rootCert, _ := cert.DERToX509Cert(derBytes)

	// when
	valid, NoErr := hecdsa.VerifyWithCert(rootCert, signature, message, signerOpt)

	// then
	assert.NoError(t, NoErr)
	assert.True(t, valid)
}
