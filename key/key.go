package key

type keyType string

const (
	PRIVATE_KEY keyType = "pri"
	PUBLIC_KEY	keyType = "pub"
)

type Key interface {

	SKI() (ski []byte)

	Algorithm() KeyGenOpts

	ToPEM() ([]byte,error)

	Type() (keyType)

}