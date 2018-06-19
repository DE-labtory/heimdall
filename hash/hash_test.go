package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/it-chain/heimdall"
)

func TestHashManager_Hash(t *testing.T) {

	rawData := []byte("This data will be hashed by hashManager")

	// normal case
	digest, err := Hash(rawData, nil, heimdall.SHA512)
	assert.NoError(t, err)
	assert.NotNil(t, digest)

	// compare between hashed data by the same hash function
	anotherDigest, err := Hash(rawData, nil, heimdall.SHA512)
	assert.Equal(t, digest, anotherDigest)

	// compare between hashed data by the different hash function
	anotherDigest, err = Hash(rawData, nil, heimdall.SHA256)
	assert.NotEqual(t, digest, anotherDigest)

}
