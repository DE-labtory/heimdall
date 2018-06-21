// This file provides components that is needed for loading key process.

package key

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"github.com/it-chain/heimdall"
)

// keyLoader contains path as a string.
type keyLoader struct {
	path string
}

// keyInfos contains key related information such as id, key generation option and key type.
type keyInfos struct {
	id         string
	keyGenOpts heimdall.KeyGenOpts
	keyType    heimdall.KeyType
}

// Load loads private key and public key from stored file.
func (loader *keyLoader) Load() (pri heimdall.PriKey, pub heimdall.PubKey, err error) {

	if _, err := os.Stat(loader.path); os.IsNotExist(err) {

		return nil, nil, errors.New("keys are not exist")
	}

	files, err := ioutil.ReadDir(loader.path)
	if err != nil {
		return nil, nil, errors.New("failed to read key repository directory")
	}

	for _, file := range files {

		keyInfos, ok := loader.getKeyInfos(file.Name())
		if !ok {
			return nil, nil, errors.New("failed to get key informations")
		}

		keyByte, err := loader.loadKeyBytes(keyInfos.id, keyInfos.keyGenOpts, keyInfos.keyType)
		if err != nil {
			return nil, nil, errors.New("failed to get key bytes by loading key file")
		}

		switch keyInfos.keyType {
		case heimdall.PRIVATE_KEY:
			pri, err = PEMToPrivateKey(keyByte, keyInfos.keyGenOpts)
			if err != nil {
				return nil, nil, err
			}

		case heimdall.PUBLIC_KEY:
			pub, err = PEMToPublicKey(keyByte, keyInfos.keyGenOpts)
			if err != nil {
				return nil, nil, err
			}

		default:
			return nil, nil, errors.New("wrong key type entered")
		}

	}

	if pri == nil || pub == nil {
		return nil, nil, errors.New("failed to load Key")
	}

	return pri, pub, nil

}

// loadKeyBytes reads key bytes from file.
func (loader *keyLoader) loadKeyBytes(alias string, keyGenOpt heimdall.KeyGenOpts, keyType heimdall.KeyType) (keyByte []byte, err error) {
	if len(alias) == 0 {
		return nil, errors.New("input value should not be blank")
	}

	path, err := loader.getFullPath(alias, keyGenOpt.String(), string(keyType))
	if err != nil {
		return nil, err
	}

	keyByte, err = ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return keyByte, nil
}

// getKeyInfos gets key information that are id, key generation option and key type.
func (loader *keyLoader) getKeyInfos(name string) (*keyInfos, bool) {

	datas := strings.Split(name, "_")

	if len(datas) != 3 {
		return nil, false
	}

	keyGenOpts, ok := heimdall.StringToKeyGenOpts(datas[1])
	if !ok {
		return nil, false
	}

	keyType := heimdall.KeyType(datas[2])
	if !(keyType == heimdall.PRIVATE_KEY || keyType == heimdall.PUBLIC_KEY) {
		return nil, false
	}

	infos := &keyInfos{
		id:         datas[0],
		keyGenOpts: keyGenOpts,
		keyType:    keyType,
	}

	return infos, true

}

// getFullPath gets full (absolute) path of a key file.
func (loader *keyLoader) getFullPath(alias, keyGenOpt string, suffix string) (string, error) {
	if _, err := os.Stat(loader.path); os.IsNotExist(err) {
		err = os.MkdirAll(loader.path, 0755)
		if err != nil {
			return "", err
		}
	}

	return filepath.Join(loader.path, alias+"_"+keyGenOpt+"_"+suffix), nil
}
