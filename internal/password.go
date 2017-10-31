package internal

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
)

type PasswordCrypter struct {
	stdin io.Reader
}

func (c PasswordCrypter) Name() string {
	return "password"
}

func (c PasswordCrypter) Encrypt(plaintext string, encryptParams EncryptParams) (Ciphertext, DecryptParams, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", nil, fmt.Errorf("Error generating salt: %s", err)
	}
	key, err := c.getKey(salt)
	if err != nil {
		return "", nil, fmt.Errorf("Error generating encryption key: %s", err)
	}

	ciphertext, err := AESEncrypt(key, plaintext, encryptParams)
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
	stdin := c.stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	reader := bufio.NewReader(stdin)
	fmt.Print("Enter password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return []byte(nil), fmt.Errorf("Error reading password: %s", err)
	}
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 24)
}
