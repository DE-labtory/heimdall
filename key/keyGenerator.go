// This file provides key generator interface.

package key

import "github.com/it-chain/heimdall"

// keyGenerator represents a key generator.
type keyGenerator interface {

	// Generate generates public and private key that match the input key generation option.
	Generate(opts heimdall.KeyGenOpts) (pri heimdall.PriKey, pub heimdall.PubKey, err error)
}
