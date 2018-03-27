package hash

type hashManagerImpl struct {

	hasher map[HashOpts]hasher
}

func NewHashManager(opts HashOpts) (HashManager, error) {

	hasher := make(map[HashOpts]hasher)

}