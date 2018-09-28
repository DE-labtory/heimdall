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

// This file provides ECDSA signing and verifying related functions.

package hecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"

	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

	"strconv"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/hashing"
)

var ErrInvalidSignature = [...]error{
	errors.New("invalid signature - garbage follows signature"),
	errors.New("invalid signature - signature's R value should not be nil"),
	errors.New("invalid signature - signature's S value should not be nil"),
	errors.New("invalid signature - signature's R value should be positive except zero"),
	errors.New("invalid signature - signature's S value should be positive except zero"),
}

var ErrCertGenTimeIsFuture = errors.New("invalid certificate - certificate's generated time is not past time")
var ErrCertExpired = errors.New("invalid certificate - certificate is expired")
var ErrCertRevoked = errors.New("invalid certificate - revoked certificate")
var ErrNoRootCertInPath = errors.New("no root certificate in certificate directory path")

// ecdsaSignature contains ECDSA signature components that are two big integers, R and S.
type ecdsaSignature struct {
	R, S *big.Int
}

// marshalECDSASignature returns encoding format (ASN.1) of signature.
func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{r, s})
}

// unmarshalECDSASignature parses the ASN.1 structure to ECDSA signature.
func unmarshalECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	ecdsaSig := new(ecdsaSignature)
	rest, err := asn1.Unmarshal(signature, ecdsaSig)
	if err != nil {
		return nil, nil, err
	}

	if len(rest) != 0 {
		return nil, nil, ErrInvalidSignature[0]
	}

	if ecdsaSig.R == nil {
		return nil, nil, ErrInvalidSignature[1]
	}

	if ecdsaSig.S == nil {
		return nil, nil, ErrInvalidSignature[2]
	}

	if ecdsaSig.R.Sign() != 1 {
		return nil, nil, ErrInvalidSignature[3]
	}

	if ecdsaSig.S.Sign() != 1 {
		return nil, nil, ErrInvalidSignature[4]
	}

	return ecdsaSig.R, ecdsaSig.S, nil
}

type Signer struct {
}

// Sign generates signature for a data using private key.
func (signer *Signer) Sign(pri heimdall.PriKey, message []byte, opts heimdall.SignerOpts) ([]byte, error) {
	digest, err := hashing.Hash(message, opts.HashOpt())
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, pri.(*PriKey).internalPriKey, digest)
	if err != nil {
		return nil, err
	}

	signature, err := marshalECDSASignature(r, s)
	if err != nil {
		return nil, err
	}

	// remove private key from memory.
	defer pri.Clear()

	return signature, nil
}

type Verifier struct {
}

// Verify verifies the signature using pubKey(public key) and digest of original message, then returns boolean value.
func (verifier *Verifier) Verify(pub heimdall.PubKey, signature, message []byte, opts heimdall.SignerOpts) (bool, error) {
	digest, err := hashing.Hash(message, opts.HashOpt())
	if err != nil {
		return false, err
	}

	r, s, err := unmarshalECDSASignature(signature)
	if err != nil {
		return false, err
	}

	valid := ecdsa.Verify(pub.(*PubKey).internalPubKey, digest, r, s)
	return valid, nil
}

// VerifyWithCert verify a signature with certificate.
func (verifier *Verifier) VerifyWithCert(cert *x509.Certificate, signature, message []byte, opts heimdall.SignerOpts) (bool, error) {
	pub := NewPubKey(cert.PublicKey.(*ecdsa.PublicKey))
	return verifier.Verify(pub, signature, message, opts)
}

type CertVerifier struct {
}

// VerifyCertChain verifies a certificate from local certificates in certificate store directory.
func (cv *CertVerifier) VerifyCertChain(cert *x509.Certificate, certDirPath string) error {
	roots, err := makeRootsPool(certDirPath)
	if err != nil {
		return err
	}

	intermediates, err := makeIntermediatesPool(certDirPath)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}

// makeRootsPool makes certificate pool of root certificates in certificate store directory.
func makeRootsPool(certDirPath string) (rootsPool *x509.CertPool, err error) {
	rootsPool = x509.NewCertPool()

	files, err := ioutil.ReadDir(certDirPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		certFilePath := filepath.Join(certDirPath, file.Name())
		certPEMBlock, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			return nil, err
		}

		cert, err := heimdall.PemToX509Cert(certPEMBlock)
		if cert.IsCA == true && bytes.Compare(cert.RawIssuer, cert.RawSubject) == 0 {
			rootsPool.AddCert(cert)
		}
	}

	if len(rootsPool.Subjects()) == 0 {
		return nil, ErrNoRootCertInPath
	}

	return rootsPool, nil
}

// makeIntermediatesPool makes certificate pool of intermediate certificates in certificate store directory.
func makeIntermediatesPool(certDirPath string) (intermediatesPool *x509.CertPool, err error) {
	intermediatesPool = x509.NewCertPool()

	files, err := ioutil.ReadDir(certDirPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		certFilePath := filepath.Join(certDirPath, file.Name())
		certPEMBlock, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			return nil, err
		}

		cert, err := heimdall.PemToX509Cert(certPEMBlock)
		if cert.IsCA == true && bytes.Compare(cert.RawIssuer, cert.RawSubject) != 0 {
			intermediatesPool.AddCert(cert)
		}
	}

	return intermediatesPool, nil
}

// VerifyCert verifies a certificate's validity.
func (cv *CertVerifier) VerifyCert(cert *x509.Certificate) error {
	// check if expired or invalid generation time
	err := checkTime(cert.NotBefore, cert.NotAfter)
	if err != nil {
		return err
	}

	// check if revoked
	for _, url := range cert.CRLDistributionPoints {
		crl, err := requestCRL(url)
		if err != nil {
			return err
		}

		err = checkRevocation(cert, crl)
		if err != nil {
			return err
		}
	}

	return nil
}

// checkTime checks if entered certificate's generated/expired time is valid.
func checkTime(notBefore time.Time, notAfter time.Time) error {
	if time.Now().Before(notBefore) {
		return ErrCertGenTimeIsFuture
	}

	if time.Now().After(notAfter) {
		return ErrCertExpired
	}

	return nil
}

// requestCRL requests CRL(Certificate Revocation List) from CRLDistributionURL.
func requestCRL(url string) (*pkix.CertificateList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL - http status code :[" + strconv.Itoa(resp.StatusCode) + "]")
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCRL(body)
}

// checkRevocation checks if entered certificate is revoked by CRL(Certificate Revocation List).
func checkRevocation(cert *x509.Certificate, crl *pkix.CertificateList) error {
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return ErrCertRevoked
		}
	}

	return nil
}
