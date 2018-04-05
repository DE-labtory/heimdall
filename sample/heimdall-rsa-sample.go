package main

import (
	"fmt"
	"log"
	"os"

	"reflect"

	"github.com/it-chain/heimdall/auth"
	"github.com/it-chain/heimdall/hashing"
	"github.com/it-chain/heimdall/key"
)

/*
This sample shows data to be transmitted
is signed and verified by RSA Key.
*/

func main() {

	keyManager, err := key.NewKeyManager("")
	errorCheck(err)

	keyPath := keyManager.GetPath()

	// defer os.RemoveAll("./.keyRepository")

	// if there is no key file in default key directory, then generate key.
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		keyManager.GenerateKey(key.RSA4096)
		errorCheck(err)
	}

	pri, pub, err := keyManager.GetKey()
	errorCheck(err)

	bytePriKey, err := pri.ToPEM()
	bytePubKey, err := pub.ToPEM()

	// reconstruct key pair in bytes to key.
	err = keyManager.ByteToKey(bytePriKey, key.RSA4096, key.PRIVATE_KEY)
	err = keyManager.ByteToKey(bytePubKey, key.RSA4096, key.PUBLIC_KEY)
	errorCheck(err)

	// get the reconstructed key pair.
	recPri, recPub, err := keyManager.GetKey()

	// compare reconstructed key pair with original key pair.
	if reflect.DeepEqual(pri, recPri) && reflect.DeepEqual(pub, recPub) {
		print("recovoer complete!")
	}

	sampleData := []byte("This is sample data from heimdall.")

	hashManager, err := hashing.NewHashManager()
	errorCheck(err)

	digest, err := hashManager.Hash(sampleData, nil, hashing.SHA256)
	errorCheck(err)

	authManager, err := auth.NewAuth()
	errorCheck(err)

	signerOpts := auth.EQUAL_SHA256.SignerOptsToPSSOptions()

	signature, err := authManager.Sign(pri, digest, signerOpts)
	errorCheck(err)

	/* --------- After data transmitted --------- */
	ok, err := authManager.Verify(pub, signature, digest, signerOpts)
	errorCheck(err)

	fmt.Println(ok)

}

func errorCheck(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
