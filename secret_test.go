package secretcrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecret(t *testing.T) {
	secret := secret{
		crypter:       plainCrypter{},
		ciphertext:    "abc",
		decryptParams: decryptParams{"k1": "v1", "k2": "v2"},
	}
	assert.Equal(t, "abc", secret.Decrypt())
}
