package secretcrypt

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
	assert.Nil(t, err)
	defer os.RemoveAll(tmpDir)
	pathGetter = tmpKeyPathGetter{tmpDir}

	localCrypter := localCrypter{}

	secret, _, err := localCrypter.encrypt("mypass", nil)
	assert.NoError(t, err)
	secret2, _, err := localCrypter.encrypt("mypass2", nil)
	assert.NoError(t, err)

	plaintext, err := localCrypter.decrypt(secret, nil)
	assert.NoError(t, err)
	plaintext2, err := localCrypter.decrypt(secret2, nil)
	assert.NoError(t, err)

	assert.Equal(t, "mypass", plaintext)
	assert.Equal(t, "mypass2", plaintext2)

	_, keyFilePath, _ := pathGetter.keyPaths()
	_, err = os.Stat(keyFilePath)
	assert.NoError(t, err)
}
