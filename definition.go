/*
 * Copyright 2018 It-chain
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// This file provides definition of constant and variables for globally used.

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