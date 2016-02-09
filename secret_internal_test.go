package secretcrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalText(t *testing.T) {
	var secret secret
	err := secret.UnmarshalText([]byte("plain:k1=v1&k2=v2:my-abc"))
	assert.Nil(t, err)
	assert.Equal(t, "plain", secret.crypter.name())
	assert.Equal(t, "my-abc", string(secret.ciphertext))
	assert.Equal(t, decryptParams{
		"k1": "v1",
		"k2": "v2",
	}, secret.decryptParams)
}
