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
	"encoding/pem"
)


func TestNewCertStore(t *testing.T) {
	certStore, err := NewCertStore(TestCertDir)
	assert.NoError(t, err)
	assert.NotNil(t, certStore)
}

func TestCertStore_StoreCert(t *testing.T) {
	certStore, _ := NewCertStore(TestCertDir)
	pri, _ := GenerateKey(TestCurveOpt)
	derBytes, err := x509.CreateCertificate(rand.Reader, &testCertTemplate, &testCertTemplate, &pri.PublicKey, pri)
	assert.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: derBytes,
	})

	err = certStore.StoreCert(pemBytes)
	assert.NoError(t, err)
	// defer os.RemoveAll(TestCert)
}

func TestCertStore_LoadCert(t *testing.T) {
	certStore, _ := NewCertStore(TestCertDir)
	pri, _ := GenerateKey(TestCurveOpt)
	testCertTemplate.SubjectKeyId = SKIFromPubKey(&pri.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &testCertTemplate, &testCertTemplate, &pri.PublicKey, pri)
	assert.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: derBytes,
	})

	err = certStore.StoreCert(pemBytes)

	certStore, _ = NewCertStore(TestCertDir)
	testCert, err := certStore.LoadCert(PubKeyToKeyID(&pri.PublicKey))
	assert.NoError(t, err)
	assert.NotNil(t, testCert)
	// defer os.RemoveAll(TestCert)
}
