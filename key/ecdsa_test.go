package key

import (
	"testing"

	"crypto/elliptic"

	"github.com/stretchr/testify/assert"
)

var ecdsaCurve = ECDSAKeyGenerator{curve: elliptic.P521()}
var keyGenOption = KeyGenOpts(ECDSA521)

func TestECDSAKeyPairGeneration(t *testing.T) {
	pri, pub, err := ecdsaCurve.Generate(keyGenOption)
	assert.NoError(t, err)
	assert.NotNil(t, pri)
	assert.NotNil(t, pub)
}

func TestECDSAKeyPairSKI(t *testing.T) {
	pri, pub, _ := ecdsaCurve.Generate(keyGenOption)

	priSki := pri.SKI()
	assert.NotNil(t, priSki)

	pubSki := pub.SKI()
	assert.NotNil(t, pubSki)
}

func TestECDSAGetAlgorithm(t *testing.T) {
	pri, pub, _ := ecdsaCurve.Generate(keyGenOption)

	priKeyOption := pri.Algorithm()
	assert.NotNil(t, priKeyOption)

	pubKeyOption := pub.Algorithm()
	assert.NotNil(t, pubKeyOption)
}

func TestECDSAGetPublicKey(t *testing.T) {
	pri, _, _ := ecdsaCurve.Generate(keyGenOption)

	pub, err := pri.PublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pub)
}

func TestECDSAKeyToPEM(t *testing.T) {
	pri, pub, _ := ecdsaCurve.Generate(keyGenOption)

	priPEM, err := pri.ToPEM()
	assert.NoError(t, err)
	assert.NotNil(t, priPEM)

	pubPEM, err := pub.ToPEM()
	assert.NoError(t, err)
	assert.NotNil(t, pubPEM)
}

func TestGetType(t *testing.T) {
	pri, pub, _ := ecdsaCurve.Generate(keyGenOption)

	priType := pri.Type()
	assert.Equal(t, priType, PRIVATE_KEY, "They should be equal")

	pubType := pub.Type()
	assert.Equal(t, pubType, PUBLIC_KEY, "They should be equal")
}
