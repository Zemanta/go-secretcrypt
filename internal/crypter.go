package internal

var crypters = []Crypter{
	KMSCrypter{},
	LocalCrypter{},
	PlainCrypter{},
}

// CryptersMap contains a mapping to supported crypters
var CryptersMap map[string]Crypter

// Ciphertext is the encrypted plaintext
type Ciphertext string

// EncryptParams are parameters used for encrypting a secret
type EncryptParams map[string]string

// DecryptParams are parameters used for decrypting a secret
type DecryptParams map[string]string

// Crypter is an object that knows how to encrypt and decrypt a secret
type Crypter interface {
	Name() string
	Encrypt(string, EncryptParams) (Ciphertext, DecryptParams, error)
	Decrypt(Ciphertext, DecryptParams) (string, error)
}

func init() {
	CryptersMap = make(map[string]Crypter)
	for _, crypter := range crypters {
		CryptersMap[crypter.Name()] = crypter
	}
}
