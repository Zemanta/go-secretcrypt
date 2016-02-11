package internal

type PlainCrypter struct{}

func (pc PlainCrypter) Name() string {
	return "plain"
}

func (pc PlainCrypter) Encrypt(plaintext string, encryptParams EncryptParams) (Ciphertext, DecryptParams, error) {
	return Ciphertext(plaintext), nil, nil
}

func (pc PlainCrypter) Decrypt(myCiphertext Ciphertext, decryptParams DecryptParams) (string, error) {
	return string(myCiphertext), nil
}
