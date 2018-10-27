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
)

// directories for test
var WorkingDir, _ = os.Getwd()
var RootDir = filepath.Dir(WorkingDir)
var TestKeyDir = filepath.Join(WorkingDir, "./.testKeys")
var TestPriKeyDir = filepath.Join(WorkingDir, "./.private_key")
var TestPubKeyDir = filepath.Join(WorkingDir, "./.public_keys")
var TestCertDir = filepath.Join(WorkingDir, "./.testCerts")
