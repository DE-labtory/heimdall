package heimdall

// KeyStore
type KeyStore interface {
	// StoreKey stores key as file.
	StoreKey(keys ...Key) error

	// GetKey gets the key pair from keyManagerImpl struct.
	GetKey(ski []byte) (Key, error)

	// RemoveKey removes key files.
	RemoveKey(ski []byte) error

	// GetPath returns path of key files
	GetPath() string
}
