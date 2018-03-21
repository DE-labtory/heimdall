package key

type keyGenerator interface {

	Generate(opts KeyGenOpts) (pri, pub Key, err error)

}