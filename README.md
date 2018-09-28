# Heimdall
[![Build Status](https://travis-ci.org/it-chain/heimdall.svg?branch=master)](https://travis-ci.org/it-chain/heimdall)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Language](https://img.shields.io/badge/language-go-orange.svg)](https://golang.org)
[![Coverage Status](https://coveralls.io/repos/github/it-chain/heimdall/badge.svg?branch=master)](https://coveralls.io/github/it-chain/heimdall?branch=master)
<p align="center">
<img src="./logo.png" width="210" height="210" />
</p>

<p align="center"><i>Heimdall</i> is a simple library for signing and verifying messages written by Golang.</p><br>

## Definition of Heimdall

- In Norse mythology, *[Heimdall](https://en.wikipedia.org/wiki/Heimdallr)* guarded the [*Bifrost*](https://en.wikipedia.org/wiki/Bifröst), which the Vikings believed rainbows came from

- *[Heimdall](http://marvelcinematicuniverse.wikia.com/wiki/Heimdall)* also appears in the Marvel cinematic universe.

  > **Heimdall** is the all-seeing and all-hearing Asgardian and former guard of the Bifrost Bridge.



## Getting Started with Heimdall

### Installation

```
go get -u github.com/it-chain/heimdall
```

### Usage

#### 1. Load crypto configuration (maybe from configuration file)

```Go
// In this sample, we use default configuration that equals to use heimdall.NewDefaultConfig()
myConfig, err := heimdall.NewConfig(
    192,                        // security level
    heimdall.TestKeyDir,        // key directory path
    heimdall.TestCertDir,       // certificate directory path
    "AES-CTR",                  // encryption algorithm and operation mode name
    "ECDSA",                    // signing algorithm name
    "scrypt",                   // key derivation function name
    heimdall.DefaultScrpytParams, // key derivation function parameters
)
```

#### 2. Generate key pair

```Go
// Generate key pair
privateKey, err := heimdall.GenerateKey(myConfig.CurveOpt)

// public key can be obtained like below
publicKey := &privateKey.PublicKey
```

#### 3. Minimize key size (bytes <--> key)
The key bytes from these functions have a component for recovering the key.

```Go
// private key to bytes(from bytes)
bytePri := heimdall.PriKeyToBytes(privateKey)
recPri, err := heimdall.BytesToPriKey(bytePri, myConfig.CurveOpt)

// public key to bytes(from bytes)
bytePub := heimdall.PubKeyToBytes(publicKey)
recPub, err := heimdall.BytesToPubKey(bytePub, myConfig.CurveOpt)
```

#### 4. Key ID
Keys can be identified by below key ID with prefix that is "IT" for it-chain. <br>
Key IDs from private key and public key are equal, so we use public key .

```Go
// key ID from public key directly
keyId := PubKeyToKeyID(publicKey)

// key ID from SKI(Subject Key Identifier) used in certificate
ski := heimdall.SKIFromPubKey(publicKey)
keyId := heimdall.SKIToKeyID(ski)

// SKI from key ID
recSki := heimdall.SKIFromKeyID(keyId)
```

#### 5. Store and load key by keystore

```Go
// make new keystore
ks, err := heimdall.NewKeyStore(myConFig.KeyDirPath, myConFig.Kdf, myConFig.KdfParams, myConFig.EncAlgo, myConFig.EncKeyLength)

// storing private key with password for encryption of private key
err = ks.StoreKey(privateKey, "password")

// load private key by key ID and password
loadedPri, err := ks.LoadKey(keyId, "password")
```

#### 6. Store and load certificate by certstore
Assume that 'cert' is a x.509 certificate of 'publicKey' which can be identified by 'keyId'

```Go
// make certstore
certstore, err := heimdall.NewCertStore(myConFig.CertDirPath)

// store certificate as .crt file named as its key ID
err = certstore.StoreCert(cert)

// load certificate by key ID
cert, err = certstore.LoadCert(keyId string)
```

#### 7. Verify certificate

```Go
// verify certificate chain (check if the chain of trust is right in local)
err = certstore.VerifyCertChain(cert)

// verify certificate (check if expired or revoked)
timeValid, notRevoked, err := heimdall.VerifyCert(cert)
```

#### 8. Make signature for data and verify the signature

```Go
sampleData := []byte("This is sample data for signing and verifying.")

// signing (making signature)
signature, err := heimdall.Sign(pri, sampleData, nil, myConFig.HashOpt)

/* --------- After data transmitted --------- */
/* --------- In receiver node --------- */
// verify signature with public key
ok, err := heimdall.Verify(pub, signature, sampleData, nil, myConFig.HashOpt)
// verify signature with certificate
ok, err = heimdall.VerifyWithCert(clientCert, signature, sampleData, nil, myConFig.HashOpt)

```

## Features 

### Signature algorithms

Currently, we support following Signature algorithms with options to provide wide selection range of key length.
- [ECDSA](https://en.wikipedia.org/wiki/ECDSA) ( 224 / 256 / 384 / 512 )

### Hash functions

You can make hash data by using `SHA` Algorithm with various type.
- [SHA](https://en.wikipedia.org/wiki/Secure_Hash_Algorithms) ( 224 / 256 / 384 / 512 )

### Default key storage path
If you enter empty path for your keystore such as "", your private key will be stored in below location.

```
(Current Directory)/.heimdall/.key
```

## Lincese

*Heimdall* source code files are made available under the Apache License, Version 2.0 (Apache-2.0), located in the [LICENSE](LICENSE) file.

