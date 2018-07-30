// This file provides interfaces of Key, Private key and Public key.

package heimdall

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/btcsuite/btcutil/base58"
	"encoding/hex"
	"strings"
)


// GenerateKey generates ECDSA key pair.
func GenerateKey(curveOpt CurveOpts) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curveOpt.CurveOptToCurve(), rand.Reader)
}

// PriKeyToBytes converts private key to byte format.
func PriKeyToBytes(pri *ecdsa.PrivateKey) []byte {
	return pri.D.Bytes()
}

// BytesToPriKey converts key bytes to private key format.
func BytesToPriKey(d []byte, curveOpt CurveOpts) (*ecdsa.PrivateKey, error) {
	pri := new(ecdsa.PrivateKey)
	pri.PublicKey.Curve = curveOpt.CurveOptToCurve()

	if 8 * len(d) != pri.Params().BitSize {
		return nil, errors.New("invalid private key - wrong length of key bytes for the entered curve option")
	}
	pri.D = new(big.Int).SetBytes(d)

	if pri.D.Cmp(pri.Params().N) >= 0 {
		return nil, errors.New("invalid private key - private key must be smaller than N of curve")
	}

	if pri.D.Sign() <= 0 {
		return nil, errors.New("invalid private key - private key should be positive value")
	}

	pri.PublicKey.X, pri.PublicKey.Y = pri.PublicKey.Curve.ScalarBaseMult(d)
	if pri.PublicKey.X == nil {
		return nil, errors.New("invalid private key - public key X component must not be nil")
	}

	return pri, nil
}

// PubKeyToBytes converts public key to byte format.
func PubKeyToBytes(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

// BytesToPubKey converts key bytes to public key format.
func BytesToPubKey(keyBytes []byte, curveOpt CurveOpts) (*ecdsa.PublicKey, error) {
	curve := curveOpt.CurveOptToCurve()
	x, y := elliptic.Unmarshal(curve, keyBytes)

	if x == nil {
		return new(ecdsa.PublicKey), errors.New("")
	}

	return &ecdsa.PublicKey{X: x, Y: y, Curve: curve}, nil
}

// SKI obtains Subject Key Identifier from ECDSA public key.
func SKIFromPubKey(key *ecdsa.PublicKey) (ski []byte) {
	if key == nil {
		return nil
	}

	data := PubKeyToBytes(key)

	hash := sha256.New()
	hash.Write(data)

	return hash.Sum(nil)
}

func PubKeyToKeyID(key *ecdsa.PublicKey) string{
	return keyIDPrefix + base58.Encode(SKIFromPubKey(key))
}

func SKIToKeyID(ski []byte) string {
	return keyIDPrefix + base58.Encode(ski)
}

func SKIFromKeyID(keyId string) []byte {
	return base58.Decode(keyId)
}

func RemoveKeyMem(pri *ecdsa.PrivateKey)  {
	pri.D = new(big.Int)
}

func SKIValidCheck(keyId string, ski string) error {
	skiBytes, err := hex.DecodeString(ski)
	if err != nil {
		return err
	}

	if SKIToKeyID(skiBytes) != keyId {
		return errors.New("invalid SKI - SKI is not correspond to key ID")
	}

	return nil
}

func KeyIDPrefixCheck(keyId string) error {
	if strings.HasPrefix(keyId, keyIDPrefix) != true {
		return errors.New("invalid key ID - wrong prefix")
	}

	return nil
}