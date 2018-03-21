package key

import (
	"crypto/elliptic"
	"crypto/ecdsa"
	"fmt"
	"errors"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"crypto/sha256"
)

type ECDSAKeyGenerator struct {
	curve elliptic.Curve
}

func (keygen *ECDSAKeyGenerator) Generate(opts KeyGenOpts) (pri, pub Key, err error) {

	if keygen.curve == nil {
		return nil, nil, errors.New("Curve value have not to be nil")
	}

	generatedKey, err := ecdsa.GenerateKey(keygen.curve, rand.Reader)

	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate ECDSA key : %s", err)
	}

	pri = &ECDSAPrivateKey{generatedKey}
	pub, err = pri.(*ECDSAPrivateKey).PublicKey()
	if err != nil {
		return nil, nil, err
	}

	return pri, pub, nil

}

type ECDSAPrivateKey struct {
	priv *ecdsa.PrivateKey
}

func (key *ECDSAPrivateKey) SKI() ([]byte) {

	if key.priv == nil {
		return nil
	}

	data := elliptic.Marshal(key.priv.Curve, key.priv.PublicKey.X, key.priv.PublicKey.Y)

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)

}

func (key *ECDSAPrivateKey) Algorithm() KeyGenOpts {
	return convertToKeyGenOpts(key.priv.Curve)
}

func (key *ECDSAPrivateKey) PublicKey() (Key, error) {
	return &ECDSAPublicKey{&key.priv.PublicKey}, nil
}

func (key *ECDSAPrivateKey) ToPEM() ([]byte,error){
	keyData, err := x509.MarshalECPrivateKey(key.priv)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type: "ECDSA PRIVATE KEY",
			Bytes: keyData,
		},
	), nil
}

func (key *ECDSAPrivateKey) Type() (keyType){
	return PRIVATE_KEY
}

type ECDSAPublicKey struct {
	pub *ecdsa.PublicKey
}

func (key *ECDSAPublicKey) SKI() ([]byte) {

	if key.pub == nil {
		return nil
	}

	data := elliptic.Marshal(key.pub.Curve, key.pub.X, key.pub.Y)

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)

}

func (key *ECDSAPublicKey) Algorithm() KeyGenOpts {
	return convertToKeyGenOpts(key.pub.Curve)
}

func (key *ECDSAPublicKey) ToPEM() ([]byte,error){
	keyData, err := x509.MarshalPKIXPublicKey(key.pub)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type: "ECDSA PUBLIC KEY",
			Bytes: keyData,
		},
	), nil
}

func (key *ECDSAPublicKey) Type() (keyType){
	return PUBLIC_KEY
}

func convertToKeyGenOpts(curve elliptic.Curve) (KeyGenOpts) {

	switch curve {
	case elliptic.P224():
		return ECDSA224
	case elliptic.P256():
		return ECDSA256
	case elliptic.P384():
		return ECDSA384
	case elliptic.P521():
		return ECDSA521
	}

}