// This file implements hash manager for hashing process.

package heimdall

import (
	"crypto/sha1"
	"crypto/sha512"
	"errors"
	"hash"
)

// Hash hashes the input data.
func Hash(data []byte, preBuffer []byte, opts HashOpts) ([]byte, error) {

	if data == nil {
		return nil, errors.New("data should not be NIL")
	}

	var selectedHash hash.Hash

	switch opts {
	case SHA1:
		selectedHash = sha1.New()
	case SHA224:
		selectedHash = sha512.New512_224()
	case SHA256:
		selectedHash = sha512.New512_256()
	case SHA384:
		selectedHash = sha512.New384()
	case SHA512:
		selectedHash = sha512.New()
	default:
		return nil, errors.New("invalid hash opts")
	}

	selectedHash.Write(data)
	return selectedHash.Sum(preBuffer), nil

}
