package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalText(t *testing.T) {
	var secret secret
	err := secret.UnmarshalText([]byte("plain:k1=v1&k2=v2:my-abc"))
	assert.Nil(t, err)
	assert.Equal(t, "plain", secret.crypter.Name())
	assert.Equal(t, "my-abc", string(secret.ciphertext))
	assert.Equal(t, DecryptParams{
		"k1": "v1",
		"k2": "v2",
	}, secret.decryptParams)
}
