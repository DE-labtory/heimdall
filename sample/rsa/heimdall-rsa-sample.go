package main

import (
	"fmt"
	"log"
	"reflect"

	"os"

	"github.com/it-chain/heimdall"
	"github.com/it-chain/heimdall/auth"
	"github.com/it-chain/heimdall/hash"
	"github.com/it-chain/heimdall/key"
)

/*
This sample shows data to be transmitted
is signed and verified by RSA Key.
*/

func main() {

	pwd := []byte("myPassword")
	fmt.Println("password: myPassword")
	// Note: salt have to be unique, so do not use this for real implementation.
	salt := []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}
	// for derive 256bit key from pwd
	targetLength := 32

	// derive key from pwd
	aeskey, _ := key.DeriveKeyFromPwd(pwd, salt, targetLength)
	fmt.Println("derived key: " + string(aeskey))

	// keyManager, err := key.NewKeyManager("")
	// errorCheck(err)

	defer os.RemoveAll("./.heimdall")

	// Generate key pair with RSA algorithm.
	generator, err := key.NewRSAKeyGenerator(4096)
	pri, pub, err := generator.Generate(heimdall.RSA4096)
	errorCheck(err)
	fmt.Println("Key Generation")

	// initiate new keystore
	ks, err := key.NewKeystoreNoPwd("./.heimdall")
	errorCheck(err)

	fmt.Println(ks.GetPath())

	// store generated key pair
	err = ks.StoreKey(pri, pub)
	errorCheck(err)
	fmt.Println("Key Store OK")

	// load key pair
	ski := pri.SKI()
	//ski, err := hex.DecodeString("9c4ece9bcaebb1fd8cfd447df9131b51bbb357698d4c73b40d6eb59d288c924f")
	errorCheck(err)
	loadedPri, err := ks.GetKey(ski)
	errorCheck(err)
	loadedPub := loadedPri.(heimdall.PriKey).PublicKey()
	errorCheck(err)
	// check if the loaded key pair is same with generated key pair
	if reflect.DeepEqual(pri.SKI(), loadedPri.SKI()) && reflect.DeepEqual(pub.SKI(), loadedPub.SKI()) {
		fmt.Println("Key Load OK")
	}

	//// Convert key to PEM(byte) format.
	//bytePriKey, err := pri.ToPEM()
	//bytePubKey, err := pub.ToPEM()
	//
	//// Reconstruct key pair from bytes to key.
	//recPri, err := key.PEMToPrivateKey(bytePriKey, heimdall.RSA4096)
	//recPub, err := key.PEMToPublicKey(bytePubKey, heimdall.RSA4096)
	//errorCheck(err)
	//
	//// Compare reconstructed key pair with original key pair.
	//if reflect.DeepEqual(pri, recPri) && reflect.DeepEqual(pub, recPub) {
	//	fmt.Println("reconstruct complete!")
	//}

	sampleData := []byte("This is sample data from heimdall.")

	// Convert raw data to digest(hash value) by using SHA512 function.
	digest, err := hash.Hash(sampleData, nil, heimdall.SHA512)
	errorCheck(err)

	// The option will be used in signing process in case of using RSA key.
	signerOpts := heimdall.EQUAL_SHA512.SignerOptsToPSSOptions()

	// AuthManager makes digest(hash value) to signature with private key.
	//signature, err := auth.Sign(pri, digest, signerOpts)
	signature, err := auth.Sign(loadedPri, digest, signerOpts)
	errorCheck(err)
	fmt.Println("Sign OK")

	/* --------- After data transmitted --------- */

	// AuthManager verify that received data has any forgery during transmitting process by digest.
	// and verify that the received data is surely from the expected sender by public key.
	//ok, err := auth.Verify(pub, signature, digest, signerOpts)
	ok, err := auth.Verify(loadedPub, signature, digest, signerOpts)
	errorCheck(err)

	fmt.Println(ok)
	fmt.Println("Verify OK")

}

func errorCheck(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
