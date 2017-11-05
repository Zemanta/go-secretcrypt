package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func AESEncrypt(key []byte, plaintext string) (string, error) {
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := string(bytes.Repeat([]byte{byte(padding)}, padding))
	plaintext = plaintext + padtext

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Error creating AES cipher: %s", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("Error initializing IV: %s", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], []byte(plaintext))

	b64Ciphertext := base64.StdEncoding.EncodeToString(ciphertext)
	return b64Ciphertext, nil
}

func AESDecrypt(key []byte, b64ciphertext string) (string, error) {
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
