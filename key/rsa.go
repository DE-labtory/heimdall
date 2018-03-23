package key

import (
	"crypto/rsa"
	"fmt"
	"errors"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

type RSAKeyGenerator struct {
	bits int
}

func (keygen *RSAKeyGenerator) Generate(opts KeyGenOpts) (pri, pub Key, err error) {

	if keygen.bits <= 0 {
		return nil, nil, errors.New("Bits length should be bigger than 0")
	}

	generatedKey, err := rsa.GenerateKey(rand.Reader, keygen.bits)

	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate RSA key : %s", err)
	}

	pri = &RSAPrivateKey{priv:generatedKey, bits:keygen.bits}
	pub, err = pri.(*RSAPrivateKey).PublicKey()
	if err != nil {
		return nil, nil, err
	}

	return pri, pub, nil

}

type rsaKeyMarshalOpt struct {
	N *big.Int
	E int
}

type RSAPrivateKey struct {
	priv *rsa.PrivateKey
	bits int
}

func (key *RSAPrivateKey) SKI() ([]byte) {

	if key.priv == nil {
		return nil
	}

	data, _ := asn1.Marshal(rsaKeyMarshalOpt{
		key.priv.N, key.priv.E,
	})

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)

}

func (key *RSAPrivateKey) Algorithm() KeyGenOpts {
	return RSABitsToKeyGenOpts(key.bits)
}

func (key *RSAPrivateKey) PublicKey() (pub Key, err error) {
	return &RSAPublicKey{pub: &key.priv.PublicKey, bits: key.bits}, nil
}

func (key *RSAPrivateKey) ToPEM() ([]byte,error) {
	keyData := x509.MarshalPKCS1PrivateKey(key.priv)

	return pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: keyData,
		},
	), nil
}

func (key *RSAPrivateKey) Type() (keyType){
	return PRIVATE_KEY
}

type RSAPublicKey struct {
	pub *rsa.PublicKey
	bits int
}

func (key *RSAPublicKey) SKI() ([]byte) {

	if key.pub == nil {
		return nil
	}

	data, _ := asn1.Marshal(rsaKeyMarshalOpt{
		big.NewInt(123), 57,
	})

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func (key *RSAPublicKey) Algorithm() KeyGenOpts {
	return RSABitsToKeyGenOpts(key.bits)
}

func (key *RSAPublicKey) ToPEM() ([]byte,error) {

	keyData, err := x509.MarshalPKIXPublicKey(key.pub)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PUBLIC KEY",
			Bytes: keyData,
		},
	), nil

}

func (key *RSAPublicKey) Type() (keyType){
	return PUBLIC_KEY
}