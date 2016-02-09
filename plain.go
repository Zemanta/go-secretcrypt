package secretcrypt

type plainCrypter struct{}

func (pc plainCrypter) name() string {
	return "plain"
}

func (pc plainCrypter) encrypt(plaintext string, encryptParams encryptParams) (ciphertext, decryptParams, error) {
	return ciphertext(plaintext), nil, nil
}

func (pc plainCrypter) decrypt(myCiphertext ciphertext, decryptParams decryptParams) (string, error) {
	return string(myCiphertext), nil
}
