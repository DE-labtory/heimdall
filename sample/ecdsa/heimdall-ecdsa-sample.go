package main

import (
	"fmt"
	"log"
	"github.com/it-chain/heimdall"
	"os"
	"encoding/hex"
	"errors"
)

/*
This sample shows data to be transmitted
is signed and verified by ECDSA Key.
*/

func main() {

	defer os.RemoveAll(heimdall.TestKeyDir)

	// Generate key pair with ECDSA algorithm.
	curveOpt := heimdall.TestCurveOpt
	pri, err := heimdall.GenerateKey(curveOpt)
	errorCheck(err)
	fmt.Println("generate key success")

	// private key to bytes(from bytes)
	bytePri := heimdall.PriKeyToBytes(pri)
	recPri, err := heimdall.BytesToPriKey(bytePri, curveOpt)
	errorCheck(err)
	fmt.Println("genereted private key bytes : ", hex.EncodeToString(bytePri))

	if recPri.D.Cmp(pri.D) == 0 && recPri.X.Cmp(pri.X) == 0 && recPri.Y.Cmp(pri.Y) == 0 {
		fmt.Println("obtaining private key from byte format of private key's D component is success")
	} else {
		errorCheck(errors.New("obtaining private key from byte format of private key's D component is failed"))
	}

	// public key to bytes(from bytes)
	pub := &pri.PublicKey
	bytePub := heimdall.PubKeyToBytes(pub)
	recPub, err := heimdall.BytesToPubKey(bytePub, curveOpt)

	if recPub.X.Cmp(pub.X) == 0 && recPub.Y.Cmp(pub.Y) == 0 && recPub.Curve.IsOnCurve(pub.X, pub.Y) {
		fmt.Println("obtaining public key from public key's X, Y coordinate is success")
	} else {
		errorCheck(errors.New("obtaining public key from public key's X, Y coordinate is failed"))
	}

	// make new keystore
	ks, err := heimdall.NewKeyStore(heimdall.TestKeyDir)
	errorCheck(err)
	fmt.Println("making new keystore is success")

	// storing key
	err = ks.StoreKey(pri, "password")
	errorCheck(err)
	fmt.Println("store key success")

	// public key ---> SKI ---->  Key ID (Base58encoded SKI)
	ski := heimdall.SKIFromPubKey(pub)
	keyId := heimdall.SKIToKeyID(ski)
	errorCheck(heimdall.KeyIDPrefixCheck(keyId))
	fmt.Println("keyID : ", len(keyId), keyId)
	// key ID ---> SKI
	recSki := heimdall.SKIFromKeyID(keyId)
	errorCheck(heimdall.SKIValidCheck(keyId, hex.EncodeToString(recSki)))

	fmt.Println("key id to(from) ski success")

	// load private key by key id and password
	loadedPri, err := ks.LoadKey(keyId, "password")
	errorCheck(err)
	if loadedPri.D.Cmp(pri.D) == 0 && loadedPri.X.Cmp(pri.X) == 0 && loadedPri.Y.Cmp(pri.Y) == 0 {
		fmt.Println("loading private key by key id success")
	} else {
		errorCheck(errors.New("loading private key by key id failed"))
	}

	fmt.Println("loaded private key bytes : ", hex.EncodeToString(heimdall.PriKeyToBytes(loadedPri)))

	sampleData := []byte("This is sample data for signing and verifying.")

	// Convert raw data to digest(hash value) by using SHA512 function.
	digest, err := heimdall.Hash(sampleData, nil, heimdall.SHA512)
	errorCheck(err)
	fmt.Println("Hashing success")

	// signing (making signature)
	signature, err := heimdall.Sign(pri, digest)
	errorCheck(err)
	fmt.Println("signing success")

	/* --------- After data transmitted --------- */

	// verifying signature
	ok, err := heimdall.Verify(pub, signature, digest)
	errorCheck(err)

	fmt.Println("verifying result : ", ok)
}

func errorCheck(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
