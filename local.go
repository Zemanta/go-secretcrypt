package secretcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"sync"

	"github.com/mitchellh/go-homedir"
)

type localCrypter struct{}

var keyCached []byte
var keyCacheLock sync.RWMutex

var pathGetter keyPathGetter = userDataKeyPathGetter{}

func (c localCrypter) name() string {
	return "local"
}

func (c localCrypter) encrypt(plaintext string, encryptParams encryptParams) (ciphertext, decryptParams, error) {
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := string(bytes.Repeat([]byte{byte(padding)}, padding))
	plaintext = plaintext + padtext

	key, err := localKey()
	if err != nil {
		return "", nil, fmt.Errorf("Error retrieving local key: %s", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, fmt.Errorf("Error creating AES cipher: %s", err)
	}

	myCiphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := myCiphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", nil, fmt.Errorf("Error initializing IV: %s", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(myCiphertext[aes.BlockSize:], []byte(plaintext))

	return ciphertext(myCiphertext), nil, nil
}

func (c localCrypter) decrypt(myCiphertext ciphertext, decryptParams decryptParams) (string, error) {
	key, err := localKey()
	if err != nil {
		return "", fmt.Errorf("Error retrieving local key: %s", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Error creating AES cipher: %s", err)
	}

	if len(myCiphertext) < aes.BlockSize {
		return "", fmt.Errorf("Ciphertext too short in secret '%s'", myCiphertext)
	}
	iv := []byte(myCiphertext[:aes.BlockSize])
	myCiphertext = myCiphertext[aes.BlockSize:]

	if len(myCiphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("Ciphertext is not a multiple of the block size in secret '%s'", myCiphertext)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(myCiphertext))
	mode.CryptBlocks(plaintext, []byte(myCiphertext))

	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	plaintext = plaintext[:(length - unpadding)]
	return string(plaintext), nil
}

func localKey() ([]byte, error) {
	keyCacheLock.RLock()
	key := keyCached
	keyCacheLock.RUnlock()

	if len(key) == 0 {
		keyCacheLock.Lock()
		defer keyCacheLock.Unlock()
		key = keyCached

		if len(key) == 0 {
			// retrieve or generate key
			keyDir, keyFilePath, err := pathGetter.keyPaths()
			if err != nil {
				return nil, err
			}

			// if key file already exists
			if _, err := os.Stat(keyFilePath); err == nil {
				key, err = ioutil.ReadFile(keyFilePath)
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
			err = ioutil.WriteFile(keyFilePath, key, 0644)
			if err != nil {
				return nil, err
			}
		}
	}
	return key, nil
}

type keyPathGetter interface {
	keyPaths() (string, string, error)
}

type userDataKeyPathGetter struct{}

func (g userDataKeyPathGetter) keyPaths() (string, string, error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		return "", "", err
	}

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
