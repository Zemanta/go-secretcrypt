package internal

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

type tmpKeyPathGetter struct {
	tmpdir string
}

func (g tmpKeyPathGetter) keyPaths() (string, string, error) {
	dir := path.Join(g.tmpdir, "secretcrypt")
	return dir, path.Join(dir, "key"), nil
}

func TestLocal(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	pathGetter = tmpKeyPathGetter{tmpDir}

	localCrypter := LocalCrypter{}

	secret, _, err := localCrypter.Encrypt("mypass", nil)
	assert.NoError(t, err)
	secret2, _, err := localCrypter.Encrypt("mypass2", nil)
	assert.NoError(t, err)

	plaintext, err := localCrypter.Decrypt(secret, nil)
	assert.NoError(t, err)
	plaintext2, err := localCrypter.Decrypt(secret2, nil)
	assert.NoError(t, err)

	assert.Equal(t, "mypass", plaintext)
	assert.Equal(t, "mypass2", plaintext2)

	_, keyFilePath, _ := pathGetter.keyPaths()
	_, err = os.Stat(keyFilePath)
	assert.NoError(t, err)
}

func TestLocalErrors(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	pathGetter = tmpKeyPathGetter{tmpDir}

	localCrypter := LocalCrypter{}

	secret, _, err := localCrypter.Encrypt("mypass", nil)
	assert.NoError(t, err)

	plaintext, err := localCrypter.Decrypt("@Most_certainly: NOT, Base64 !!!", nil)
	assert.Error(t, err, "not base64 cypher text should return error")
	assert.Zero(t, plaintext)
	plaintext, err = localCrypter.Decrypt("", nil)
	assert.Error(t, err, "empty cypher text should return error")
	assert.Zero(t, plaintext)
	plaintext, err = localCrypter.Decrypt("Zm9v", nil)
	assert.Error(t, err, "too short cypher text should return error")
	assert.Zero(t, plaintext)

	plaintext, err = localCrypter.Decrypt(secret, nil)
	assert.NoError(t, err)

	assert.Equal(t, "mypass", plaintext)
}
