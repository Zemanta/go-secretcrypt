package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPassword(t *testing.T) {
	crypter := PasswordCrypter{
		readPassword: func(fd int) ([]byte, error) {
			return []byte("mypass"), nil
		},
	}

	secret, decryptParams, err := crypter.Encrypt("myplaintext", nil)
	assert.NoError(t, err)

	plaintext, err := crypter.Decrypt(secret, decryptParams)
	assert.NoError(t, err)

	assert.Equal(t, "myplaintext", plaintext)
}
