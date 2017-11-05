package internal

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"syscall"
)

type PasswordCrypter struct {
	readPassword func(int) ([]byte, error)
}

func (c PasswordCrypter) Name() string {
	return "password"
}

func (c PasswordCrypter) Encrypt(plaintext string, encryptParams EncryptParams) (Ciphertext, DecryptParams, error) {
	rawSalt := make([]byte, 16)
	_, err := rand.Read(rawSalt)
	if err != nil {
		return "", nil, fmt.Errorf("Error generating salt: %s", err)
	}
	salt := base64.StdEncoding.EncodeToString(rawSalt)
	key, err := c.getKey([]byte(salt))
	if err != nil {
		return "", nil, fmt.Errorf("Error generating encryption key: %s", err)
	}

	ciphertext, err := AESEncrypt(key, plaintext)
	if err != nil {
		return "", nil, fmt.Errorf("Error encrypting plaintext: %s", err)
	}
	decryptParams := DecryptParams{"salt": string(salt)}
	return Ciphertext(ciphertext), decryptParams, nil
}

func (c PasswordCrypter) Decrypt(b64ciphertext Ciphertext, decryptParams DecryptParams) (string, error) {
	salt, ok := decryptParams["salt"]
	if !ok {
		return "", fmt.Errorf("Missing salt!")
	}
	key, err := c.getKey([]byte(salt))
	if err != nil {
		return "", fmt.Errorf("Error retrieving encryption key: %s", err)
	}

	plaintext, err := AESDecrypt(key, string(b64ciphertext))
	if err != nil {
		return "", fmt.Errorf("Error decrypting secret: %s", err)
	}
	return string(plaintext), nil
}

func (c PasswordCrypter) getKey(salt []byte) ([]byte, error) {
	if c.readPassword == nil {
		c.readPassword = terminal.ReadPassword
	}
	fmt.Print("Enter password: ")
	password, err := c.readPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		return []byte(nil), fmt.Errorf("Error reading password: %s", err)
	}
	return scrypt.Key([]byte(password), salt, 1024, 1, 1, 24)
}
