package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"sync"

	"github.com/mitchellh/go-homedir"
)

type LocalCrypter struct{}

var keyCached []byte
var keyCacheLock sync.RWMutex

var pathGetter keyPathGetter = userDataKeyPathGetter{}

func (c LocalCrypter) Name() string {
	return "local"
}

func (c LocalCrypter) Encrypt(plaintext string, encryptParams EncryptParams) (Ciphertext, DecryptParams, error) {
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

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", nil, fmt.Errorf("Error initializing IV: %s", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], []byte(plaintext))

	b64Ciphertext := base64.StdEncoding.EncodeToString(ciphertext)
	return Ciphertext(b64Ciphertext), nil, nil
}

func (c LocalCrypter) Decrypt(b64ciphertext Ciphertext, decryptParams DecryptParams) (string, error) {
	key, err := localKey()
	if err != nil {
		return "", fmt.Errorf("Error retrieving local key: %s", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Error creating AES cipher: %s", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(string(b64ciphertext))
	if err != nil {
		return "", fmt.Errorf("Ciphertext is not valid base64 encoded in secret '%s'", b64ciphertext)
	}
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("Ciphertext too short in secret '%s'", ciphertext)
	}
	iv := []byte(ciphertext[:aes.BlockSize])
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("Ciphertext is not a multiple of the block size in secret '%s'", ciphertext)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, []byte(ciphertext))

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
