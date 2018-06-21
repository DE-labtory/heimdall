package key

import (
	"testing"

	"crypto/elliptic"

	"github.com/stretchr/testify/assert"
	"github.com/it-chain/heimdall"
)

var ecdsaCurve = ECDSAKeyGenerator{curve: elliptic.P521()}
var ECDSAkeyGenOption = heimdall.KeyGenOpts(heimdall.ECDSA521)

func TestECDSAKeyPairGeneration(t *testing.T) {
	pri, pub, err := ecdsaCurve.Generate(ECDSAkeyGenOption)
	assert.NoError(t, err)
	assert.NotNil(t, pri)
	assert.NotNil(t, pub)
}

func TestECDSAKeyPairSKI(t *testing.T) {
	pri, pub, _ := ecdsaCurve.Generate(ECDSAkeyGenOption)

	priSki := pri.SKI()
	assert.NotNil(t, priSki)

	pubSki := pub.SKI()
	assert.NotNil(t, pubSki)
}

func TestECDSAGetOpt(t *testing.T) {
	pri, pub, _ := ecdsaCurve.Generate(ECDSAkeyGenOption)

	priKeyOption := pri.GenOpt()
	assert.NotNil(t, priKeyOption)

	pubKeyOption := pub.GenOpt()
	assert.NotNil(t, pubKeyOption)
}

func TestECDSAGetPublicKey(t *testing.T) {
	pri, _, _ := ecdsaCurve.Generate(ECDSAkeyGenOption)

	pub := pri.PublicKey()
	assert.NotNil(t, pub)
}

func TestECDSAKeyToPEM(t *testing.T) {
	pri, pub, _ := ecdsaCurve.Generate(ECDSAkeyGenOption)

	priPEM, err := pri.ToPEM()
	assert.NoError(t, err)
	assert.NotNil(t, priPEM)

	pubPEM, err := pub.ToPEM()
	assert.NoError(t, err)
	assert.NotNil(t, pubPEM)
}

func TestGetECDSAKeyType(t *testing.T) {
	pri, pub, _ := ecdsaCurve.Generate(ECDSAkeyGenOption)

	priType := pri.Type()
	assert.Equal(t, priType, heimdall.PRIVATE_KEY, "They should be equal")

	pubType := pub.Type()
	assert.Equal(t, pubType, heimdall.PUBLIC_KEY, "They should be equal")
}
