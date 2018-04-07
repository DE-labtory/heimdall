# Heimdall

*Heimdall* is a simple library that keeps your data secure through signing and verification written by Golang.

### Definition of Heimdall

- In Norse mythology, *[Heimdall](https://en.wikipedia.org/wiki/Heimdallr)* guarded the [*Bifrost*](https://en.wikipedia.org/wiki/Bifröst), which the Vikings believed rainbows came from

- *[Heimdall](http://marvelcinematicuniverse.wikia.com/wiki/Heimdall)* also appears in the Marvel cinematic universe.

  > **Heimdall** is the all-seeing and all-hearing Asgardian and former guard of the Bifrost Bridge.



## Getting Started with Heimdall

### Installation

```
go get -u github.com/it-chain/heimdall
```

### Usage

```Go
keyManager, err := NewKeyManager(".myKeys")

// Generate a pair of key with RSA Algorithm
priv, pub, err := keyManager.GenerateKey(key.RSA4096)

sampleData = []byte("This is the data will be transmitted.")

hashManager, err := hashing.NewHashManager()

// Convert raw data to hashed data by using SHA512 function
digest, err := hashManager.Hash(sampleData, nil, hashing.SHA512)

authManager, err := auth.NewAuth()

// The option will be used in signing process in case of using RSA key
signerOpts := auth.EQUAL_SHA256.SignerOptsToPSSOptions()

// AuthManager make hashed-data(digest) to signature with the generated private key
signature, err := authManager.Sign(priv, digest, signerOpts)

/* --------- After data transmitted --------- */

// AuthManager verify that received data has any forgery during transmitting process
ok, err := authManager.Verify(pub, signature, digest, signerOpts)

fmt.println(ok) // true
```

## Features 

### Asymmetric key algorithms

Currently, we support following asymmetric key generation algorithms with options to provide wide selection range.
- [RSA](https://en.wikipedia.org/wiki/RSA) ( 1024 / 2048 / 4096 )
- [ECDSA](https://en.wikipedia.org/wiki/ECDSA) ( 224 / 256 / 384 / 512 )

### Hash functions

You can make hash data by using `SHA` Algorithm with various type.

- [SHA](https://en.wikipedia.org/wiki/Secure_Hash_Algorithms) ( 224 / 256 / 384 / 512 )

### Default key storage path
If you input empty path such as "", we store a pair of the key in below location.

```
(Current Directory)/.keyRepository
```

## Lincese

*Heimdall* source code files are made available under the Apache License, Version 2.0 (Apache-2.0), located in the [LICENSE](LICENSE) file.

