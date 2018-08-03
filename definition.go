// This file provides definition of constant and variables for globally used.

package heimdall

import (
	"os"
	"path/filepath"
	"encoding/hex"
	"crypto/x509"
	"math/big"
	"crypto/x509/pkix"
	"time"
)


// Key ID prefix
const keyIDPrefix = "IT"

// directories for test
var WorkingDir, _ = os.Getwd()
var RootDir = filepath.Dir(WorkingDir)
var TestKeyDir = filepath.Join(WorkingDir, "./.testKeys")
var TestCertDir = filepath.Join(WorkingDir, "./.testCerts")

// Parameters for test
const TestCurveOpt = SECP256R1
const TestHashOpt = SHA512

// Note: salt have to be unique, so do not use this for real implementation.
var TestSalt = []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}
var TestScrpytParams = map[string]string{
	"n" : ScryptN,
	"r" : ScryptR,
	"p" : ScryptP,
	"keyLen" : ScryptKeyLen,
	"salt" : hex.EncodeToString([]byte("saltsalt")),
}

var testCertTemplate = x509.Certificate{
	IsCA: true,
	SubjectKeyId: []byte{1,2,3},
	SerialNumber: big.NewInt(1),
	Subject: pkix.Name{
		Country: []string{"Korea"},
		Organization: []string{"it-chain co"},
		OrganizationalUnit: []string{"authentication division"},
	},
	NotBefore: time.Now(),
	NotAfter: time.Now().Add(time.Hour * 24 * 180),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}