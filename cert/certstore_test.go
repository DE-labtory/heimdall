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

package cert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"os"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/cert"
	"github.com/it-chain/heimdall/hecdsa"
	"github.com/it-chain/heimdall/mocks"
	"github.com/stretchr/testify/assert"
)

func TestCertStorer_StoreCert(t *testing.T) {
	// given
	rootPri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootPub := &rootPri.PublicKey
	assert.NoError(t, err)
	hRootPri := hecdsa.NewPriKey(rootPri)

	mocks.TestRootCertTemplate.SubjectKeyId = hRootPri.SKI()
	derBytes, err := x509.CreateCertificate(rand.Reader, &mocks.TestRootCertTemplate, &mocks.TestRootCertTemplate, rootPub, rootPri)
	assert.NoError(t, err)
	rootCert, _ := cert.DERToX509Cert(derBytes)

	// when
	err = cert.Store(rootCert, heimdall.TestCertDir)

	// then
	assert.NoError(t, err)

	defer os.RemoveAll(heimdall.TestCertDir)
}

func TestCertLoader_LoadCert(t *testing.T) {
	// given
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

	keyId := hRootPri.ID()

	// when
	testCert, err := cert.Load(keyId, heimdall.TestCertDir)

	// then
	assert.NoError(t, err)
	assert.Equal(t, rootCert, testCert)

	defer os.RemoveAll(heimdall.TestCertDir)
}
