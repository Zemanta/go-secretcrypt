package secretcrypt

var crypters = []crypter{
	plainCrypter{},
}

var cryptersMap map[string]crypter

type ciphertext string
type encryptParams map[string]string
type decryptParams map[string]string

type crypter interface {
	name() string
	encrypt(string, encryptParams) (ciphertext, decryptParams, error)
	decrypt(ciphertext, decryptParams) (string, error)
}

func init() {
	cryptersMap = make(map[string]crypter)
	for _, crypter := range crypters {
		cryptersMap[crypter.name()] = crypter
	}
}
