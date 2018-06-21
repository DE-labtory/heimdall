// This file implement ECDSA key and its generation.

package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/it-chain/heimdall"
)

// ECDSAPrivateKey contains private key of ECDSA.
type ECDSAPrivateKey struct {
	PrivKey *ecdsa.PrivateKey
}

// SKI provides name of file that will be store a ECDSA private key.
func (key *ECDSAPrivateKey) SKI() (ski []byte) {

	if key.PrivKey == nil {
		return nil
	}

	data := elliptic.Marshal(key.PrivKey.Curve, key.PrivKey.PublicKey.X, key.PrivKey.PublicKey.Y)

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)

}

// Algorithm returns key generation option of ECDSA.
func (key *ECDSAPrivateKey) GenOpt() heimdall.KeyGenOpts {
	return heimdall.ECDSACurveToKeyGenOpts(key.PrivKey.Curve)
}

// PublicKey returns ECDSA public key of key pair.
func (key *ECDSAPrivateKey) PublicKey() heimdall.PubKey {
	return &ECDSAPublicKey{&key.PrivKey.PublicKey}
}

// ToPEM makes a ECDSA private key to PEM format.
func (key *ECDSAPrivateKey) ToPEM() ([]byte, error) {
	keyData, err := x509.MarshalECPrivateKey(key.PrivKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "ECDSA PRIVATE KEY",
			Bytes: keyData,
		},
	), nil
}

// Type returns type of the ECDSA private key.
func (key *ECDSAPrivateKey) Type() heimdall.KeyType {
	return heimdall.PRIVATE_KEY
}

// ECDSAPublicKey contains components of a public key.
type ECDSAPublicKey struct {
	PubKey *ecdsa.PublicKey
}

// SKI provides name of file that will be store a ECDSA public key.
func (key *ECDSAPublicKey) SKI() (ski []byte) {

	if key.PubKey == nil {
		return nil
	}

	data := elliptic.Marshal(key.PubKey.Curve, key.PubKey.X, key.PubKey.Y)

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)

}

// Algorithm returns ECDSA public key generation option.
func (key *ECDSAPublicKey) GenOpt() heimdall.KeyGenOpts {
	return heimdall.ECDSACurveToKeyGenOpts(key.PubKey.Curve)
}

// ToPEM makes a ECDSA public key to PEM format.
func (key *ECDSAPublicKey) ToPEM() ([]byte, error) {
	keyData, err := x509.MarshalPKIXPublicKey(key.PubKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "ECDSA PUBLIC KEY",
			Bytes: keyData,
		},
	), nil
}

// Type returns type of the ECDSA public key.
func (key *ECDSAPublicKey) Type() heimdall.KeyType {
	return heimdall.PUBLIC_KEY
}
