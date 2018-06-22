package heimdall

// KeyStore
type KeyStore interface {
	// StoreKey stores key as file.
	StoreKey() error

	// GetKey gets the key pair from keyManagerImpl struct.
	GetKey(ski []byte) (Key, err error)

	// RemoveKey removes key files.
	RemoveKey() error

	// GetPath returns path of key files
	GetPath() string
}