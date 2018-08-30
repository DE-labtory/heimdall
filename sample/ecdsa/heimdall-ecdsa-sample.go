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

package main

import (
	"log"
	"github.com/it-chain/heimdall"
	"encoding/hex"
	"errors"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/rand"
	"os"
	"net/http/httptest"
	"crypto/x509/pkix"
	"math/big"
	"time"
	"net/http"
	"io"
)

/*
This sample shows data to be transmitted
is signed and verified by ECDSA Key.
*/

func main() {

	// load configuration (usually from file)
	// params : secLv - int
	// 			keyDirPath - string
	// 			certDirPath - string
	// 			encAlgo - string
	// 			sigAlgo - string
	// 			kdf - string
	// 			kdfParams - map[string]string
	// In sample code, we use default config that equals to heimdall.NewDefaultConfig()
	myConFig, err := heimdall.NewConfig(
		192,
		heimdall.TestKeyDir,
		heimdall.TestCertDir,
		"AES-CTR",
		"ECDSA",
		"scrypt",
		heimdall.DefaultScrpytParams,
	)
	errorCheck(err)

	defer os.RemoveAll(myConFig.CertDirPath)
	defer os.RemoveAll(myConFig.KeyDirPath)

	// Generate key pair with ECDSA algorithm.
	curveOpt := myConFig.CurveOpt
	pri, err := heimdall.GenerateKey(curveOpt)
	errorCheck(err)
	log.Println("1. generate key success")

	// public key to bytes(from bytes)
	pub := &pri.PublicKey
	bytePub := heimdall.PubKeyToBytes(pub)
	recPub, err := heimdall.BytesToPubKey(bytePub, curveOpt)

	if recPub.X.Cmp(pub.X) == 0 && recPub.Y.Cmp(pub.Y) == 0 && recPub.Curve.IsOnCurve(pub.X, pub.Y) {
		log.Println("obtaining public key from public key's X, Y coordinate is success")
	} else {
		errorCheck(errors.New("obtaining public key from public key's X, Y coordinate is failed"))
	}

	// private key to bytes(from bytes)
	bytePri := heimdall.PriKeyToBytes(pri)
	recPri, err := heimdall.BytesToPriKey(bytePri, curveOpt)
	errorCheck(err)
	log.Println("genereted private key bytes : ", hex.EncodeToString(bytePri))

	if recPri.D.Cmp(pri.D) == 0 && recPri.X.Cmp(pri.X) == 0 && recPri.Y.Cmp(pri.Y) == 0 {
		log.Println("obtaining private key from byte format of private key's D component is success")
	} else {
		errorCheck(errors.New("obtaining private key from byte format of private key's D component is failed"))
	}

	// public key ---> SKI ---->  Key ID (Base58encoded SKI)
	ski := heimdall.SKIFromPubKey(pub)
	keyId := heimdall.SKIToKeyID(ski)
	errorCheck(heimdall.KeyIDPrefixCheck(keyId))
	log.Println("keyID : ", len(keyId), keyId)
	// key ID ---> SKI
	recSki := heimdall.SKIFromKeyID(keyId)
	errorCheck(heimdall.SKIValidCheck(keyId, hex.EncodeToString(recSki)))

	log.Println("key id to(from) ski success")

	// make new keystore
	ks, err := heimdall.NewKeyStore(myConFig.KeyDirPath, myConFig.Kdf, myConFig.KdfParams, myConFig.EncAlgo, myConFig.EncKeyLength)
	errorCheck(err)
	log.Println("2. making new keystore is success")

	// storing key
	err = ks.StoreKey(pri, "password")
	errorCheck(err)
	log.Println("3. store key success")

	// load private key by key id and password
	loadedPri, err := ks.LoadKey(keyId, "password")
	errorCheck(err)
	if loadedPri.D.Cmp(pri.D) == 0 && loadedPri.X.Cmp(pri.X) == 0 && loadedPri.Y.Cmp(pri.Y) == 0 {
		log.Println("loading private key by key id success")
	} else {
		errorCheck(errors.New("loading private key by key id failed"))
	}

	log.Println("loaded private key bytes : ", hex.EncodeToString(heimdall.PriKeyToBytes(loadedPri)))

	////////////////////// config CA for sample
	rootCert, clientCert, sampleCA, err := configCA(&pri.PublicKey)
	errorCheck(err)
	log.Println("4. request and receive certificate from rootCA")
	//////////////////////////////////////////////////////////////////

	// make certstore
	certstore, err := heimdall.NewCertStore(myConFig.CertDirPath)
	errorCheck(err)
	log.Println("5. make cert store")

	// store certificates from CA
	err = certstore.StoreCert(rootCert)
	errorCheck(err)
	log.Println("6-1. store root certificate")
	err = certstore.StoreCert(clientCert)
	errorCheck(err)
	log.Println("6-2. store client certificate")

	// verify certificate chain
	log.Println("7. verify certificate chain")
	err = certstore.VerifyCertChain(clientCert)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("valid certificate chain")
	}

	// set CRL distribution point
	clientCert.CRLDistributionPoints = []string{sampleCA.URL}
	// verify cert with rootCert (can be intermediate cert between root and client)
	log.Println("8. verify certificate")
	timeValid, notRevoked, err := heimdall.VerifyCert(clientCert)
	errorCheck(err)
	if !timeValid {
		log.Println("error - certificate is expired")
	} else if !notRevoked {
		log.Println("error - certificate is revoked")
	} else if timeValid && notRevoked {
		log.Println("valid certificate")
	}


	sampleData := []byte("This is sample data for signing and verifying.")

	// signing (making signature)
	signature, err := heimdall.Sign(pri, sampleData, nil, myConFig.HashOpt)
	errorCheck(err)
	log.Println("make signature(signing) message")

	/* --------- After data transmitted --------- */

	// verifying signature with public key
	ok, err := heimdall.Verify(pub, signature, sampleData, nil, myConFig.HashOpt)
	errorCheck(err)
	log.Println("verifying with public key result : ", ok)

	ok, err = heimdall.VerifyWithCert(clientCert, signature, sampleData, nil, myConFig.HashOpt)
	errorCheck(err)
	log.Println("verifying with certificate result : ", ok)
}

func errorCheck(err error) {
	if err != nil {
		log.Panicln(err)
	}
}

func configCA(pub *ecdsa.PublicKey) (rootCert, clientCert *x509.Certificate, sampleCA *httptest.Server, err error) {
	rootPri, err := heimdall.GenerateKey(heimdall.TestCurveOpt)
	errorCheck(err)
	rootPub := &rootPri.PublicKey

	heimdall.TestRootCertTemplate.SubjectKeyId = heimdall.SKIFromPubKey(rootPub)
	heimdall.TestCertTemplate.SubjectKeyId = heimdall.SKIFromPubKey(pub)

	rootDerBytes, err := x509.CreateCertificate(rand.Reader, &heimdall.TestRootCertTemplate, &heimdall.TestRootCertTemplate, rootPub, rootPri)
	errorCheck(err)
	clientDerBytes, err := x509.CreateCertificate(rand.Reader, &heimdall.TestCertTemplate, &heimdall.TestRootCertTemplate, pub, rootPri)
	errorCheck(err)

	rootCert, err = heimdall.DERToX509Cert(rootDerBytes)
	errorCheck(err)
	clientCert, err = heimdall.DERToX509Cert(clientDerBytes)
	errorCheck(err)

	// revoked certificate
	revokedCertificate := new(pkix.RevokedCertificate)
	revokedCertificate.SerialNumber = big.NewInt(44)
	revokedCertificate.RevocationTime = time.Now()
	revokedCertificate.Extensions = nil

	revokedCertList := []pkix.RevokedCertificate{*revokedCertificate}

	// create CRL
	crlBytes, err := rootCert.CreateCRL(rand.Reader, rootPri, revokedCertList, time.Now(), time.Now().Add(time.Hour * 24))
	errorCheck(err)

	// httptest server
	sampleCA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, string(crlBytes))
	}))


	return rootCert, clientCert, sampleCA, nil
}
