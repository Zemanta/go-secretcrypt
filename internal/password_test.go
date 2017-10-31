package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"strings"
)

func TestPassword(t *testing.T) {
	crypter := PasswordCrypter{}

	crypter.stdin = strings.NewReader("mypass\n")
	secret, decryptParams, err := crypter.Encrypt("myplaintext", nil)
	assert.NoError(t, err)

	crypter.stdin = strings.NewReader("mypass\n")
	plaintext, err := crypter.Decrypt(secret, decryptParams)
	assert.NoError(t, err)

	assert.Equal(t, "myplaintext", plaintext)
}
