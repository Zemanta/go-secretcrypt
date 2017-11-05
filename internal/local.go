package internal

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"runtime"
	"sync"
)

type LocalCrypter struct{}

var keyCached []byte
var keyCacheLock sync.RWMutex

var pathGetter keyPathGetter = userDataKeyPathGetter{}

func (c LocalCrypter) Name() string {
	return "local"
}

func (c LocalCrypter) Encrypt(plaintext string, encryptParams EncryptParams) (Ciphertext, DecryptParams, error) {
	key, err := localKey()
	if err != nil {
		return "", nil, fmt.Errorf("Error retrieving local key: %s", err)
	}

	ciphertext, err := AESEncrypt(key, plaintext)
	if err != nil {
		return "", nil, fmt.Errorf("Error encrypting plaintext: %s", err)
	}
	return Ciphertext(ciphertext), nil, nil
}

func (c LocalCrypter) Decrypt(b64ciphertext Ciphertext, decryptParams DecryptParams) (string, error) {
	key, err := localKey()
	if err != nil {
		return "", fmt.Errorf("Error retrieving local key: %s", err)
	}

	plaintext, err := AESDecrypt(key, string(b64ciphertext))
	if err != nil {
		return "", fmt.Errorf("Error decrypting secret: %s", err)
	}
	return string(plaintext), nil
}

func localKey() ([]byte, error) {
	keyCacheLock.RLock()
	key := keyCached
	keyCacheLock.RUnlock()

	if len(key) > 0 {
		return key, nil
	}

	keyCacheLock.Lock()
	defer keyCacheLock.Unlock()
	key = keyCached

	if len(key) > 0 {
		return key, nil
	}
	// retrieve or generate key
	keyDir, keyFilePath, err := pathGetter.keyPaths()
	if err != nil {
		return nil, err
	}

	// if key file already exists
	if _, err := os.Stat(keyFilePath); err == nil {
		keyB64, err := ioutil.ReadFile(keyFilePath)
		if err != nil {
			return nil, err
		}
		key, err = base64.StdEncoding.DecodeString(string(keyB64))
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	// else generate the key
	key = make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		return nil, err
	}
	// and write it into the key file
	err = os.MkdirAll(keyDir, 0755)
	if err != nil {
		return nil, err
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)
	err = ioutil.WriteFile(keyFilePath, []byte(keyB64), 0644)
	if err != nil {
		return nil, err
	}
	return key, nil
}

type keyPathGetter interface {
	keyPaths() (string, string, error)
}

type userDataKeyPathGetter struct{}

func (g userDataKeyPathGetter) keyPaths() (string, string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", "", err
	}
	homeDir := currentUser.HomeDir

	var dataDir string
	switch runtime.GOOS {
	case "darwin":
		dataDir = "Library/Application Support"
	case "windows":
		dataDir = "AppData\\Local\\"
	default:
		dataDir = os.Getenv("XDG_DATA_HOME")
		if len(dataDir) == 0 {
			dataDir = ".local/share"
		}
	}
	keyDir := path.Join(homeDir, dataDir, "secretcrypt")
	return keyDir, path.Join(keyDir, "key"), nil
}
