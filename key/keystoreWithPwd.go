package key

import "github.com/it-chain/heimdall"

type keystoreWithPwd struct {
	path string
}

// StoreKey stores key as file.
func (ks *keystoreWithPwd) StoreKey(keys ...heimdall.Key) error {
	return nil
}

// GetKey gets the key pair from keyManagerImpl struct.
func (ks *keystoreWithPwd) GetKey(ski []byte) (heimdall.Key, error) {
	return nil, nil
}

// RemoveKey removes key files.
func (ks *keystoreWithPwd) RemoveKey(ski []byte) error {
	return nil
}

// GetPath returns path of key files
func (ks *keystoreWithPwd) GetPath() string {
	return ""
}
