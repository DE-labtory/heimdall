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

package mocks

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

var TestRootCertTemplate = x509.Certificate{
	Version:      1,
	SerialNumber: big.NewInt(1),
	IsCA:         true,
	SubjectKeyId: []byte{1, 2, 3},

	Subject: pkix.Name{
		Country:            []string{"KR"},
		Province:           []string{"Seoul"},
		PostalCode:         []string{"12312"},
		StreetAddress:      []string{"street123"},
		Organization:       []string{"it-chain co"},
		OrganizationalUnit: []string{"it-chain co"},
		CommonName:         string("it-chain central"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter:  time.Now().Add(time.Hour * 24 * 180),

	KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

var TestIntermediateCertTemplate = x509.Certificate{
	Version:      1,
	SerialNumber: big.NewInt(2),
	IsCA:         true,
	SubjectKeyId: []byte{4, 5, 6},

	Subject: pkix.Name{
		Country:            []string{"KR"},
		Province:           []string{"Seoul"},
		PostalCode:         []string{"12312"},
		StreetAddress:      []string{"street123"},
		Organization:       []string{"it-chain co"},
		OrganizationalUnit: []string{"development division"},
		CommonName:         string("it-chain dev"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter:  time.Now().Add(time.Hour * 24 * 180),

	KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

var TestCertTemplate = x509.Certificate{
	Version:      1,
	SerialNumber: big.NewInt(3),
	IsCA:         false,
	SubjectKeyId: []byte{7, 8, 9},

	Subject: pkix.Name{
		Country:            []string{"KR"},
		Province:           []string{"Seoul"},
		PostalCode:         []string{"12312"},
		StreetAddress:      []string{"street123"},
		Organization:       []string{"it-chain co"},
		OrganizationalUnit: []string{"Development Division", "Authentication Team"},
		CommonName:         string("it-chain dev-auth"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter:  time.Now().Add(time.Hour * 24 * 180),

	KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

var TestExpiredCertTemplate = x509.Certificate{
	Version:      1,
	SerialNumber: big.NewInt(101),
	IsCA:         false,
	SubjectKeyId: []byte{7, 8, 9},

	Subject: pkix.Name{
		Country:            []string{"KR"},
		Province:           []string{"Seoul"},
		PostalCode:         []string{"12312"},
		StreetAddress:      []string{"street123"},
		Organization:       []string{"it-chain co"},
		OrganizationalUnit: []string{"Development Division", "Authentication Team"},
		CommonName:         string("it-chain dev-auth"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter:  time.Now().Add(time.Second * 5),

	KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}

var TestRevokedCertTemplate = x509.Certificate{
	Version:      1,
	SerialNumber: big.NewInt(44),
	IsCA:         false,
	SubjectKeyId: []byte{7, 8, 9},

	Subject: pkix.Name{
		Country:            []string{"KR"},
		Province:           []string{"Seoul"},
		PostalCode:         []string{"12312"},
		StreetAddress:      []string{"street123"},
		Organization:       []string{"it-chain co"},
		OrganizationalUnit: []string{"Development Division", "Authentication Team"},
		CommonName:         string("it-chain dev-auth"),
	},
	CRLDistributionPoints: []string{"CRL distribution URL"},

	NotBefore: time.Now(),
	NotAfter:  time.Now().Add(time.Hour * 24 * 180),

	KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	BasicConstraintsValid: true,
}
