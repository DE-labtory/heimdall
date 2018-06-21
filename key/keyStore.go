// This file provides key storing process.

package key

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"github.com/it-chain/heimdall"
)

// keyStorer contains key file path.
type keyStorer struct {
	path string
}

// Store stores the input keys to file.
func (storer *keyStorer) Store(keys ...heimdall.Key) (err error) {

	if len(keys) == 0 {
		return errors.New("input values should not be nil")
	}

	for _, key := range keys {
		err := storer.storeKey(key)

		if err != nil {
			return err
		}
	}

	return nil

}

// storeKey changes the key format to PEM and make file name, then store into file.
func (storer *keyStorer) storeKey(key heimdall.Key) error {

	var data []byte
	var err error

	if key == nil {
		return errors.New("entered key is nil")
	}

	data, err = key.ToPEM()

	if err != nil {
		return err
	}

	path, err := storer.getFullPath(hex.EncodeToString(key.SKI()), key.GenOpt().String()+"_"+string(key.Type()))

	if err != nil {
		return err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = ioutil.WriteFile(path, data, 0700)
		if err != nil {
			return err
		}
	}

	return nil

}

// getFullPath gets full (absolute) path of the key file.
func (storer *keyStorer) getFullPath(alias, suffix string) (string, error) {

	if _, err := os.Stat(storer.path); os.IsNotExist(err) {
		err = os.MkdirAll(storer.path, 0755)
		if err != nil {
			return "", err
		}
	}

	return filepath.Join(storer.path, alias+"_"+suffix), nil

}
