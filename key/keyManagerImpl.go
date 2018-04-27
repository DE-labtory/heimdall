// This file implements KeyManager.

package key

import (
	"crypto/elliptic"
	"errors"
	"os"
	"strings"
)

// KeyManagerImpl contains key file path, key generator, key loader and key storer.
type keyManagerImpl struct {
	path       string
	generators map[KeyGenOpts]keyGenerator

	loader keyLoader
	storer keyStorer
}

// NewKeyManager makes a new key manager that contains key file path, key generator, key loader, key storer.
func NewKeyManager(path string) (KeyManager, error) {

	if len(path) == 0 {
		path = "./.heimdall"
	} else {
		if !strings.HasPrefix(path, "./") {
			path = "./" + path
		} else {
			path = path
		}
	}

	if strings.HasSuffix(path, "/") {
		path = path + ".keys"
	} else {
		path = path + "/.keys"
	}

	keyGenerators := make(map[KeyGenOpts]keyGenerator)
	keyGenerators[RSA1024] = &RSAKeyGenerator{1024}
	keyGenerators[RSA2048] = &RSAKeyGenerator{2048}
	keyGenerators[RSA4096] = &RSAKeyGenerator{4096}

	keyGenerators[ECDSA224] = &ECDSAKeyGenerator{elliptic.P224()}
	keyGenerators[ECDSA256] = &ECDSAKeyGenerator{elliptic.P256()}
	keyGenerators[ECDSA384] = &ECDSAKeyGenerator{elliptic.P384()}
	keyGenerators[ECDSA521] = &ECDSAKeyGenerator{elliptic.P521()}

	loader := &keyLoader{
		path: path,
	}

	storer := &keyStorer{
		path: path,
	}

	km := &keyManagerImpl{
		path:       path,
		generators: keyGenerators,
		loader:     *loader,
		storer:     *storer,
	}

	return km, nil
}

// GenerateKey generates(returns and stores as file) public and private key pair that matches the input key generation option.
func (km *keyManagerImpl) GenerateKey(opts KeyGenOpts) (pri PriKey, pub PubKey, err error) {

	err = km.RemoveKey()
	if err != nil {
		return nil, nil, err
	}

	if !opts.ValidCheck() {
		return nil, nil, errors.New("Invalid KeyGen Options")
	}

	keyGenerator, found := km.generators[opts]
	if !found {
		return nil, nil, errors.New("Invalid KeyGen Options")
	}

	pri, pub, err = keyGenerator.Generate(opts)
	if err != nil {
		return nil, nil, errors.New("Failed to generate a Key")
	}

	err = km.storer.Store(pri, pub)
	if err != nil {
		return nil, nil, errors.New("Failed to store a Key")
	}

	return pri, pub, nil

}

// GetKey gets the key pair from keyManagerImpl struct.
// if the keyManagerImpl doesn't have any key, then get keys from stored key files.
func (km *keyManagerImpl) GetKey() (pri PriKey, pub PubKey, err error) {

	pri, pub, err = km.loader.Load()
	if err != nil {
		return nil, nil, err
	}

	return pri, pub, nil

}

// RemoveKey removes key files.
func (km *keyManagerImpl) RemoveKey() error {

	err := os.RemoveAll(km.path)
	if err != nil {
		return err
	}

	return nil

}

// GetPath returns path of key files
func (km *keyManagerImpl) GetPath() string {
	return km.path
}
