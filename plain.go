package secretcrypt

type plainCrypter struct{}

func (pc plainCrypter) name() string {
	return "plain"
}

func (pc plainCrypter) encrypt(plaintext string, encryptParams encryptParams) (ciphertext, decryptParams) {
	return ciphertext(plaintext), nil
}

func (pc plainCrypter) decrypt(myCiphertext ciphertext, decryptParams decryptParams) string {
	return string(myCiphertext)
}
