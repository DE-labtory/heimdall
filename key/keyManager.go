package key

type KeyManager interface {

	GenerateKey(opts KeyGenOpts) (pri, pub Key, err error)

	GetKey() (pri, pub Key, err error)

	RemoveKey() (error)

}

