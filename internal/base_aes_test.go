package internal

import (
	"testing"

	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"math/rand"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	keyB64 := base64.StdEncoding.EncodeToString(key)
	ciphertext, _ := AESEncrypt([]byte(keyB64), "mypass", nil)
	plaintext, _ := AESDecrypt([]byte(keyB64), ciphertext)
	assert.Equal(t, "mypass", plaintext)
}
