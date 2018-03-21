package key

type KeyManager interface {

	GenerateKey(keyGenOpt KeyGenOpts) (pri, pub Key, err error)

	GetKey() (pri, pub Key, err error)

}

