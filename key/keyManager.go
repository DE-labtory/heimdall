package key

type KeyManager interface {

	GenerateKey(opts KeyGenOpts) (pri PriKey, pub PubKey, err error)

	GetKey() (pri, pub Key, err error)

	RemoveKey() (error)

}

