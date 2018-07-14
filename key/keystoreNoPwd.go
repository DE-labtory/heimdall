package key

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"strings"

	"path"

	"encoding/hex"

	"github.com/it-chain/heimdall"
)

type keystoreNoPwd struct {
	path string
}

type keyInfo struct {
	keyGenOpts heimdall.KeyGenOpts
	keyType    heimdall.KeyType
}

func NewKeystoreNoPwd(path string) (heimdall.KeyStore, error) {
	ks := &keystoreNoPwd{}
	return ks, ks.init(path)
}

func (ks *keystoreNoPwd) init(path string) error {
	if len(path) == 0 {
		path = "./.heimdall"
	} else if !strings.HasPrefix(path, "./") {
		path = "./" + path
	}

	if strings.HasSuffix(path, "/") {
		path = path + ".keys"
	} else {
		path = path + "/.keys"
	}

	ks.path = path

	return nil
}

// StoreKey stores key as file.
// TODO: storeKey와 겹치는 이름..... 고쳐야할듯?
func (ks *keystoreNoPwd) StoreKey(keys ...heimdall.Key) error {
	if len(keys) == 0 {
		return errors.New("key(s) is(are) not entered")
	}

	for _, key := range keys {
		err := ks.storeKey(key)

		if err != nil {
			return err
		}
	}

	return nil
}

// GetKey gets the key pair from keyManagerImpl struct.
func (ks *keystoreNoPwd) GetKey(ski []byte) (key heimdall.Key, err error) {
	key, err = ks.Load(ski)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// RemoveKey removes key files.
func (ks *keystoreNoPwd) RemoveKey(ski []byte) error {
	return nil
}

// GetPath returns path of key files
func (ks *keystoreNoPwd) GetPath() string {
	return ks.path
}

// storeKey changes the key format to PEM and make file name, then store into file.
func (ks *keystoreNoPwd) storeKey(key heimdall.Key) error {
	if key == nil {
		return errors.New("entered key is nil")
	}

	data, err := key.ToPEM()
	if err != nil {
		return err
	}

	keyPath, err := ks.getFullPath(key)
	if err != nil {
		return err
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		err = ioutil.WriteFile(keyPath, data, 0700)
		if err != nil {
			return err
		}
	}

	return nil
}

// getFullPath gets full (absolute) path of the key file.
func (ks *keystoreNoPwd) getFullPath(key heimdall.Key) (string, error) {
	if _, err := os.Stat(ks.path); os.IsNotExist(err) {
		err = os.MkdirAll(ks.path, 0755)
		if err != nil {
			return "", err
		}
	}

	return filepath.Join(ks.path, hex.EncodeToString(key.SKI())+"_"+key.GenOpt().String()+"_"+string(key.Type())), nil
}

// Load loads private key and public key from stored file.
func (ks *keystoreNoPwd) Load(ski []byte) (key heimdall.Key, err error) {
	if _, err := os.Stat(ks.path); os.IsNotExist(err) {
		return nil, errors.New("no key in keystore path")
	}

	keyPath, err := ks.findKeyBySKI(ski)
	if err != nil {
		return nil, err
	}

	_, keyFileName := path.Split(keyPath)
	keyInfos, err := ks.getKeyInfos(keyFileName)
	if err != nil {
		return nil, err
	}

	keyByte, err := ks.loadKeyBytes(keyPath)
	if err != nil {
		return nil, err
	}

	switch keyInfos.keyType {
	case heimdall.PRIVATE_KEY:
		key, err = PEMToPrivateKey(keyByte, keyInfos.keyGenOpts)
		if err != nil {
			return nil, err
		}

	case heimdall.PUBLIC_KEY:
		key, err = PEMToPublicKey(keyByte, keyInfos.keyGenOpts)
		if err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("wrong key type entered")
	}

	if key == nil {
		return nil, errors.New("failed to load Key")
	}

	return key, nil
}

// findKeyBySKI finds key file path of entered subject key identifier(ski)
func (ks *keystoreNoPwd) findKeyBySKI(ski []byte) (keyPath string, err error) {
	matches, err := filepath.Glob(ks.path + "/" + hex.EncodeToString(ski) + "*pri")

	if err != nil {
		return "", err
	}

	if len(matches) == 0 {
		return "", errors.New("no match key ski in path")
	} else if len(matches) > 1 {
		return "", errors.New("there are more than one key for the entered subject key identifier")
	}

	return matches[0], nil
}

// loadKeyBytes reads key bytes from file.
func (ks *keystoreNoPwd) loadKeyBytes(keyPath string) (keyByte []byte, err error) {
	if len(keyPath) == 0 {
		return nil, errors.New("empty input key path")
	}

	keyByte, err = ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return keyByte, nil
}

// getKeyInfos gets key information that are id, key generation option and key type.
func (ks *keystoreNoPwd) getKeyInfos(name string) (keyInfo, error) {
	Infos := strings.Split(name, "_")
	keyInfos := &keyInfo{}

	if len(Infos) != 3 {
		return *keyInfos, errors.New("wrong key file name")
	}

	keyGenOpts, err := heimdall.StringToKeyGenOpts(Infos[1])
	if err != nil {
		return *keyInfos, err
	}

	keyType := heimdall.KeyType(Infos[2])
	if !(keyType == heimdall.PRIVATE_KEY || keyType == heimdall.PUBLIC_KEY) {
		return *keyInfos, errors.New("wrong key type (not pri or pub)")
	}

	keyInfos.keyType = keyType
	keyInfos.keyGenOpts = keyGenOpts

	return *keyInfos, nil
}
