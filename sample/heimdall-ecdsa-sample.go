package main

import (
	"fmt"
	"log"
	"os"

	"github.com/it-chain/heimdall/auth"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/key"
)

/*
This sample shows data to be transmitted
is signed and verified by ECDSA Key.
*/

func main() {

	keyManager, err := key.NewKeyManager("")
	errorCheck(err)

	keyPath := keyManager.GetPath()

	// defer os.RemoveAll("./.keyRepository")

	pri, pub, err := keyManager.GetKey()
	errorCheck(err)

	// if there is no key file in default key directory, then generate key.
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		pri, pub, err = keyManager.GenerateKey(key.ECDSA384)
		errorCheck(err)
	}

	sampleData := []byte("This is sample data from heimdall.")

	hashManager, err := hashing.NewHashManager()
	errorCheck(err)

	digest, err := hashManager.Hash(sampleData, nil, hashing.SHA512)
	errorCheck(err)

	authManager, err := auth.NewAuth()
	errorCheck(err)

	signature, err := authManager.Sign(pri, digest, nil)
	errorCheck(err)

	/* --------- After data transmitted --------- */
	ok, err := authManager.Verify(pub, signature, digest, nil)
	errorCheck(err)

	fmt.Println(ok)

}

func errorCheck(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
