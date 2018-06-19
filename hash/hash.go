// This file implements hash manager for hashing process.

package hash

import (
	"crypto/sha1"
	"crypto/sha512"
	"errors"
	"hash"
	"github.com/it-chain/heimdall"
)

// Hash hashes the input data.
func Hash(data []byte, tail []byte, opts heimdall.HashOpts) ([]byte, error) {

	if data == nil {
		return nil, errors.New("Data should not be NIL")
	}

	var hash hash.Hash

	switch opts {
	case heimdall.SHA1:
		hash = sha1.New()
	case heimdall.SHA224:
		hash = sha512.New512_224()
	case heimdall.SHA256:
		hash = sha512.New512_256()
	case heimdall.SHA384:
		hash = sha512.New384()
	case heimdall.SHA512:
		hash = sha512.New()
	default:
		return nil, errors.New("Invalid hash opts")
	}

	hash.Write(data)
	return hash.Sum(tail), nil

}
