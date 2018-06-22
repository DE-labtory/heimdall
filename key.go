// This file provides interfaces of Key, Private key and Public key.

package heimdall

// A KeyType represents key type such as 'public' or 'private'.
type KeyType string

const (
	PRIVATE_KEY KeyType = "pri"
	PUBLIC_KEY  KeyType = "pub"
)

// keyGenerator represents a key generator.
type KeyGenerator interface {

	// Generate generates public and private key that match the input key generation option.
	Generate(opts KeyGenOpts) (pri PriKey, pub PubKey, err error)
}

// A Key represents a cryptographic key.
type Key interface {
	// SKI provides name of file that will be store a key
	SKI() (ski []byte)

	// GenOpt returns key generation option such as 'rsa2048'.
	GenOpt() KeyGenOpts

	// ToPEM makes a key to PEM format.
	ToPEM() ([]byte, error)

	// Type returns type of the key.
	Type() KeyType
}

// PriKey represents a private key by implementing Key interface.
type PriKey interface {
	Key

	// PublicKey returns public key of key pair
	PublicKey() PubKey
}

// PubKey represents a public key by implementing Key interface.
type PubKey interface {
	Key
}
