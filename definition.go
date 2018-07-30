package heimdall

import (
	"os"
	"path/filepath"
	"encoding/hex"
)


// Key ID prefix
const keyIDPrefix = "IT"

// directories for test
var WorkingDir, _ = os.Getwd()
var RootDir = filepath.Dir(WorkingDir)
var TestKeyDir = filepath.Join(WorkingDir, "./.testKeys")

// Parameters for test
const TestCurveOpt = SECP256R1

// Note: salt have to be unique, so do not use this for real implementation.
var TestSalt = []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}
var TestScrpytParams = map[string]string{
	"n" : ScryptN,
	"r" : ScryptR,
	"p" : ScryptP,
	"keyLen" : ScryptKeyLen,
	"salt" : hex.EncodeToString([]byte("saltsalt")),
}