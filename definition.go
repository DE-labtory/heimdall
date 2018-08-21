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

// This file provides definition of constant and variables for globally used.

package heimdall

import (
	"os"
	"path/filepath"
	"crypto/x509"
	"math/big"
	"crypto/x509/pkix"
	"time"
)


// Key ID prefix
const keyIDPrefix = "IT"

// KDF functions
const SCRYPT = "scrypt"
const PBKDF2 = "pbkdf2"
const BCRYPT = "bcrypt"

// directories for test
var WorkingDir, _ = os.Getwd()
var RootDir = filepath.Dir(WorkingDir)
var TestKeyDir = filepath.Join(WorkingDir, "./.testKeys")
var TestCertDir = filepath.Join(WorkingDir, "./.testCerts")

// Parameters for test
const TestCurveOpt = SECP256R1
const TestHashOpt = SHA512


// TestConf provides configuration struct using 192 bits of security level.
var TestConf = NewDefaultConfig()
// Note: salt have to be unique, so do not use this for real implementation.
var TestSalt = []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}
// Default scrypt Parameters
var DefaultScrpytParams = map[string]string{
	// N should highest power of 2 that key derived in 100ms.
	"n" : "32768", // 1 << 15 (2^15)
	// R(blocksize parameter) : fine-tune sequential memory read size and performance. (8 is commonly used)
	"r" : "8",
	// P(Parallelization parameter) : a positive integer satisfying p ≤ (232− 1) * hLen / MFLen.
	"p" : "32" ,
}

var TestRootCertTemplate = x509.Certificate{
	Version: 1,
	SerialNumber: big.NewInt(1),
	IsCA: true,
	SubjectKeyId: []byte{1,2,3},

	Subject: pkix.Name{
		Country: []string{"KR"},
		Province: []string{"Seoul"},
		PostalCode: []string{"12312"},
		StreetAddress: []string{"street123"},
		Organization: []string{"it-chain co"},
		OrganizationalUnit: []string{"it-chain co"},
		CommonName: string("it-chain central"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter: time.Now().Add(time.Hour * 24 * 180),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

var TestIntermediateCertTemplate = x509.Certificate{
	Version: 1,
	SerialNumber: big.NewInt(2),
	IsCA: true,
	SubjectKeyId: []byte{4,5,6},

	Subject: pkix.Name{
		Country: []string{"KR"},
		Province: []string{"Seoul"},
		PostalCode: []string{"12312"},
		StreetAddress: []string{"street123"},
		Organization: []string{"it-chain co"},
		OrganizationalUnit: []string{"development division"},
		CommonName: string("it-chain dev"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter: time.Now().Add(time.Hour * 24 * 180),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

var TestCertTemplate = x509.Certificate{
	Version: 1,
	SerialNumber: big.NewInt(3),
	IsCA: false,
	SubjectKeyId: []byte{7,8,9},

	Subject: pkix.Name{
		Country: []string{"KR"},
		Province: []string{"Seoul"},
		PostalCode: []string{"12312"},
		StreetAddress: []string{"street123"},
		Organization: []string{"it-chain co"},
		OrganizationalUnit: []string{"Development Division", "Authentication Team"},
		CommonName: string("it-chain dev-auth"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter: time.Now().Add(time.Hour * 24 * 180),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

var TestExpiredCertTemplate = x509.Certificate{
	Version: 1,
	SerialNumber: big.NewInt(101),
	IsCA: false,
	SubjectKeyId: []byte{7,8,9},

	Subject: pkix.Name{
		Country: []string{"KR"},
		Province: []string{"Seoul"},
		PostalCode: []string{"12312"},
		StreetAddress: []string{"street123"},
		Organization: []string{"it-chain co"},
		OrganizationalUnit: []string{"Development Division", "Authentication Team"},
		CommonName: string("it-chain dev-auth"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter: time.Now().Add(time.Second * 5),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

var TestRevokedCertTemplate = x509.Certificate{
	Version: 1,
	SerialNumber: big.NewInt(44),
	IsCA: false,
	SubjectKeyId: []byte{7,8,9},

	Subject: pkix.Name{
		Country: []string{"KR"},
		Province: []string{"Seoul"},
		PostalCode: []string{"12312"},
		StreetAddress: []string{"street123"},
		Organization: []string{"it-chain co"},
		OrganizationalUnit: []string{"Development Division", "Authentication Team"},
		CommonName: string("it-chain dev-auth"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter: time.Now().Add(time.Hour * 24 * 180),

	KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

const TestCertPemBytes = `-----BEGIN CERTIFICATE-----
MIICfTCCAiOgAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCS1IxDjAM
BgNVBAgTBVNlb3VsMRIwEAYDVQQJEwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEy
MRQwEgYDVQQKEwtpdC1jaGFpbiBjbzEUMBIGA1UECxMLaXQtY2hhaW4gY28xGTAX
BgNVBAMTEGl0LWNoYWluIGNlbnRyYWwwHhcNMTgwODAzMDY0OTUzWhcNMTkwMTMw
MDY0OTUzWjCBiDELMAkGA1UEBhMCS1IxDjAMBgNVBAgTBVNlb3VsMRIwEAYDVQQJ
EwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEyMRQwEgYDVQQKEwtpdC1jaGFpbiBj
bzEUMBIGA1UECxMLaXQtY2hhaW4gY28xGTAXBgNVBAMTEGl0LWNoYWluIGNlbnRy
YWwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASSiQD7VeydDXkiOLCaSJ291FLb
RMaY8IZoCC6wQcgow+kJ/WgtU8QmBFKJ2NFMn13vOY4/80pui/baFaGRfanvo3ww
ejAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MA8GA1UdEwEB/wQFMAMBAf8wDAYDVR0OBAUEAwECAzAqBgNVHR8EIzAhMB+gHaAb
hhlVUkwgb2YgZGlzdHJpYnV0aW9uIHBvaW50MAoGCCqGSM49BAMCA0gAMEUCIQCO
/6n5Bwm165VAEek35c6lrOnWPbnuTvFxPXqscb5YXQIgTHNvabAeu1ma3mTflTDN
KX5s9w2er5dmDAkXxe/IDl8=
-----END CERTIFICATE-----
`

const ExpiredCertForTest = `-----BEGIN CERTIFICATE-----
MIIC6TCCAo6gAwIBAgIBZTAKBggqhkjOPQQDAjCBjTELMAkGA1UEBhMCS1IxDjAM
BgNVBAgTBVNlb3VsMRIwEAYDVQQJEwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEy
MRQwEgYDVQQKEwtpdC1jaGFpbiBjbzEdMBsGA1UECxMUZGV2ZWxvcG1lbnQgZGl2
aXNpb24xFTATBgNVBAMTDGl0LWNoYWluIGRldjAeFw0xODA4MDQwNzAwMDVaFw0x
ODA4MDQwNzAwMTBaMIGuMQswCQYDVQQGEwJLUjEOMAwGA1UECBMFU2VvdWwxEjAQ
BgNVBAkTCXN0cmVldDEyMzEOMAwGA1UEERMFMTIzMTIxFDASBgNVBAoTC2l0LWNo
YWluIGNvMTkwGwYDVQQLExREZXZlbG9wbWVudCBEaXZpc2lvbjAaBgNVBAsTE0F1
dGhlbnRpY2F0aW9uIFRlYW0xGjAYBgNVBAMTEWl0LWNoYWluIGRldi1hdXRoMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKTf9D//sPqRXxMtTi45H6s7ppqbqtwQ2
6rMeq+rZlAYNiGHU/QevtH8SGXIGL8dHNpPnoL3NhwPCCWBpXv403qOBuzCBuDAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwKQYDVR0OBCIEINpRyv26Ko5Sb41SauxaYTQrj8wgOQqou0zq
AoTOlX76MCsGA1UdIwQkMCKAIIb5Phj+oolE+L0rLNmEEj4B7JGujuYMbHevQ5Bu
HaY7MCEGA1UdHwQaMBgwFqAUoBKGEGh0dHA6Ly8xMjcuMC4wLjEwCgYIKoZIzj0E
AwIDSQAwRgIhAItz1G4+nlg1Q8HAEU9LX2P0umy7PkIb2fqOyo1K2cDcAiEAjTFd
IAFkcduGxx+qJ3Xt/xofP1dyLwzqeZgs6Fict6w=
-----END CERTIFICATE-----
`

const RootCertForTest = `-----BEGIN CERTIFICATE-----
MIICkjCCAjmgAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCS1IxDjAM
BgNVBAgTBVNlb3VsMRIwEAYDVQQJEwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEy
MRQwEgYDVQQKEwtpdC1jaGFpbiBjbzEUMBIGA1UECxMLaXQtY2hhaW4gY28xGTAX
BgNVBAMTEGl0LWNoYWluIGNlbnRyYWwwHhcNMTgwODA0MDY1MTA4WhcNMTkwMTMx
MDY1MTA4WjCBiDELMAkGA1UEBhMCS1IxDjAMBgNVBAgTBVNlb3VsMRIwEAYDVQQJ
EwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEyMRQwEgYDVQQKEwtpdC1jaGFpbiBj
bzEUMBIGA1UECxMLaXQtY2hhaW4gY28xGTAXBgNVBAMTEGl0LWNoYWluIGNlbnRy
YWwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASe/KYYGLzD61XJKqHyIyVlVIe6
Bv3SVanPKr5KZ6IqHsqRYuvFT3YUs2OSyAdwHdsC3AvRC9qsBCdgFxtSDUibo4GR
MIGOMA4GA1UdDwEB/wQEAwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwDwYDVR0TAQH/BAUwAwEB/zApBgNVHQ4EIgQg2j8M64pZFd8GkPKjOa2odnnx
TXzuJzSs5b330McUHdgwIQYDVR0fBBowGDAWoBSgEoYQaHR0cDovLzEyNy4wLjAu
MTAKBggqhkjOPQQDAgNHADBEAiBk2qbhw6Te9FbtVaKVA1S3Dzlq2h61gH0e/vTN
29mWcwIgCmQtZNqDYZofmRZeaYV7VhI9EwURBvdlu1xPZfFM9+M=
-----END CERTIFICATE-----
`

const IntermediateCertForTest = `-----BEGIN CERTIFICATE-----
MIICxTCCAmugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCS1IxDjAM
BgNVBAgTBVNlb3VsMRIwEAYDVQQJEwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEy
MRQwEgYDVQQKEwtpdC1jaGFpbiBjbzEUMBIGA1UECxMLaXQtY2hhaW4gY28xGTAX
BgNVBAMTEGl0LWNoYWluIGNlbnRyYWwwHhcNMTgwODA0MDY1MTA4WhcNMTkwMTMx
MDY1MTA4WjCBjTELMAkGA1UEBhMCS1IxDjAMBgNVBAgTBVNlb3VsMRIwEAYDVQQJ
EwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEyMRQwEgYDVQQKEwtpdC1jaGFpbiBj
bzEdMBsGA1UECxMUZGV2ZWxvcG1lbnQgZGl2aXNpb24xFTATBgNVBAMTDGl0LWNo
YWluIGRldjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCsw/CSyCiiF0p8XiS83
4N5Q2W7H5y0bwrOqL49cTK0mfacKMqEwvqqvcdjFUY99Cwr1CC6MtDdtyLk+PzWF
c7Cjgb4wgbswDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MCkGA1UdDgQiBCCkaUHdEkZfrj3VlmZT
AJnF/Mt1mHU2V9GBUNyfasWGJjArBgNVHSMEJDAigCDaPwzrilkV3waQ8qM5rah2
efFNfO4nNKzlvffQxxQd2DAhBgNVHR8EGjAYMBagFKAShhBodHRwOi8vMTI3LjAu
MC4xMAoGCCqGSM49BAMCA0gAMEUCIQD98G1mEzXvYGtLt7MD/Rm998kUSTUSXnuf
88w1aZf+4gIgP6uTKG2Jiy8l/fLxMOb3Zn9Ni4SmoX2iXE4qudx/NJw=
-----END CERTIFICATE-----
`

const ClientCertForTest = `-----BEGIN CERTIFICATE-----
MIIC6DCCAo6gAwIBAgIBAzAKBggqhkjOPQQDAjCBjTELMAkGA1UEBhMCS1IxDjAM
BgNVBAgTBVNlb3VsMRIwEAYDVQQJEwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEy
MRQwEgYDVQQKEwtpdC1jaGFpbiBjbzEdMBsGA1UECxMUZGV2ZWxvcG1lbnQgZGl2
aXNpb24xFTATBgNVBAMTDGl0LWNoYWluIGRldjAeFw0xODA4MDQwNjUxMDhaFw0x
OTAxMzEwNjUxMDhaMIGuMQswCQYDVQQGEwJLUjEOMAwGA1UECBMFU2VvdWwxEjAQ
BgNVBAkTCXN0cmVldDEyMzEOMAwGA1UEERMFMTIzMTIxFDASBgNVBAoTC2l0LWNo
YWluIGNvMTkwGwYDVQQLExREZXZlbG9wbWVudCBEaXZpc2lvbjAaBgNVBAsTE0F1
dGhlbnRpY2F0aW9uIFRlYW0xGjAYBgNVBAMTEWl0LWNoYWluIGRldi1hdXRoMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEILSk+W+xC/Y/6LkB1x5CYcLPHaiCru6
XITSeOy8XdlmH34kqRUvoIPatzQpysBoAsSb5MhydPx7gyWECnYIp6OBuzCBuDAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwKQYDVR0OBCIEIDeghCF6LsfHDuydfp10S7Qwu2zRSHHyi3Pk
618adNHuMCsGA1UdIwQkMCKAIKRpQd0SRl+uPdWWZlMAmcX8y3WYdTZX0YFQ3J9q
xYYmMCEGA1UdHwQaMBgwFqAUoBKGEGh0dHA6Ly8xMjcuMC4wLjEwCgYIKoZIzj0E
AwIDSAAwRQIge7A8ZViOcqGBN/upPM3dmJca4KeucL1g8tYk+E9tOtMCIQCB7M3+
YPaCDIl3X6u5hBf9zH9Ox9UmHO58Zm5StRksFg==
-----END CERTIFICATE-----
`

const RevokedCertForTest = `-----BEGIN CERTIFICATE-----
MIIC5zCCAo6gAwIBAgIBLDAKBggqhkjOPQQDAjCBjTELMAkGA1UEBhMCS1IxDjAM
BgNVBAgTBVNlb3VsMRIwEAYDVQQJEwlzdHJlZXQxMjMxDjAMBgNVBBETBTEyMzEy
MRQwEgYDVQQKEwtpdC1jaGFpbiBjbzEdMBsGA1UECxMUZGV2ZWxvcG1lbnQgZGl2
aXNpb24xFTATBgNVBAMTDGl0LWNoYWluIGRldjAeFw0xODA4MDQwNzAyNTZaFw0x
OTAxMzEwNzAyNTZaMIGuMQswCQYDVQQGEwJLUjEOMAwGA1UECBMFU2VvdWwxEjAQ
BgNVBAkTCXN0cmVldDEyMzEOMAwGA1UEERMFMTIzMTIxFDASBgNVBAoTC2l0LWNo
YWluIGNvMTkwGwYDVQQLExREZXZlbG9wbWVudCBEaXZpc2lvbjAaBgNVBAsTE0F1
dGhlbnRpY2F0aW9uIFRlYW0xGjAYBgNVBAMTEWl0LWNoYWluIGRldi1hdXRoMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmWduiO70gFtlzFj/F2NYkDJ3kF5ct6z0
A2Lq33O0j3dV9xmQJKBs12YVFpBfia+lrtyIX5nVmRQ6ZvXlnqAUx6OBuzCBuDAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwKQYDVR0OBCIEIKaB6llhw6BzhqVr61rr2zGGDeGeQQYYxSbL
+eXFEuH7MCsGA1UdIwQkMCKAIKtuiXs7INSR7rHB+m5538DvYZKfolfFjVuSsSSH
warFMCEGA1UdHwQaMBgwFqAUoBKGEGh0dHA6Ly8xMjcuMC4wLjEwCgYIKoZIzj0E
AwIDRwAwRAIgGoBo0MBlCBqIAwUzYrfNJejo977xCbah7wiShE7tr+0CIHgl4GM2
vfD87rXOyKhzaFGf/1xmIQw696moci3YW1XA
-----END CERTIFICATE-----
`