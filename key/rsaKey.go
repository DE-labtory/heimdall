// This file implement RSA key and its generation.

package key

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"github.com/it-chain/heimdall"
)

// rsaKeyMarshalOpt contains N and E that are RSA key's components
type rsaKeyMarshalOpt struct {
	N *big.Int
	E int
}

// RSAPrivateKey contains private key of RSA.
type RSAPrivateKey struct {
	PrivKey *rsa.PrivateKey
	Bits    int
}

// SKI provides name of file that will be store a RSA private key.
func (key *RSAPrivateKey) SKI() (ski []byte) {

	if key.PrivKey == nil {
		return nil
	}

	data, _ := asn1.Marshal(rsaKeyMarshalOpt{
		key.PrivKey.N, key.PrivKey.E,
	})

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)

}

// Algorithm returns key generation option of RSA.
func (key *RSAPrivateKey) GenOpt() heimdall.KeyGenOpts {
	return heimdall.RSABitsToKeyGenOpts(key.Bits)
}

// PublicKey returns RSA public key of key pair.
func (key *RSAPrivateKey) PublicKey() heimdall.PubKey {
	return &RSAPublicKey{PubKey: &key.PrivKey.PublicKey, Bits: key.Bits}
}

// ToPEM makes a RSA private key to PEM format.
func (key *RSAPrivateKey) ToPEM() ([]byte, error) {
	keyData := x509.MarshalPKCS1PrivateKey(key.PrivKey)

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyData,
		},
	), nil
}

// Type returns type of the RSA private key.
func (key *RSAPrivateKey) Type() heimdall.KeyType {
	return heimdall.PRIVATE_KEY
}

// RSAPublicKey contains components of a public key.
type RSAPublicKey struct {
	PubKey *rsa.PublicKey
	Bits   int
}

// SKI provides name of file that will be store a RSA public key.
func (key *RSAPublicKey) SKI() (ski []byte) {

	if key.PubKey == nil {
		return nil
	}

	data, _ := asn1.Marshal(rsaKeyMarshalOpt{
		key.PubKey.N, key.PubKey.E,
	})

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// Algorithm returns RSA public key generation option.
func (key *RSAPublicKey) GenOpt() heimdall.KeyGenOpts {
	return heimdall.RSABitsToKeyGenOpts(key.Bits)
}

// ToPEM makes a RSA public key to PEM format.
func (key *RSAPublicKey) ToPEM() ([]byte, error) {

	keyData, err := x509.MarshalPKIXPublicKey(key.PubKey)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: keyData,
		},
	), nil

}

// Type returns type of the RSA public key.
func (key *RSAPublicKey) Type() heimdall.KeyType {
	return heimdall.PUBLIC_KEY
}