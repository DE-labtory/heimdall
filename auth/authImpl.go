package auth

import "reflect"

type authImpl struct {

	signers		map[reflect.Type]signer
	verifiers	map[reflect.Type]verifier

}