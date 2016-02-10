package main

import (
	"fmt"
	"os"

	"github.com/Zemanta/go-secretcrypt"
	"github.com/Zemanta/go-secretcrypt/internal"
	"github.com/docopt/docopt-go"
	"github.com/mattn/go-isatty"
)

func encryptSecret(crypter internal.Crypter, plaintext string, encryptParams internal.EncryptParams) (secretcrypt.Secret, error) {
	ciphertext, decryptParams, err := crypter.Encrypt(plaintext, encryptParams)
	if err != nil {
		return nil, err
	}
	return internal.NewSecret(crypter, decryptParams, ciphertext), nil
}

func main() {
	usage := `Encrypts secrets. Reads secrets as user input or from standard input.

Usage:
  encrypt-secret kms [--region=<region_name>] <key_id>
  encrypt-secret local

Options:
  --region=<region_name>    AWS Region Name [default: us-east-1]
`

	arguments, _ := docopt.Parse(usage, nil, true, "0.1", false)

	var myCrypter internal.Crypter
	var encryptParams = make(internal.EncryptParams)
	if _, exists := arguments["kms"]; exists {
		myCrypter = internal.CryptersMap["kms"]
		encryptParams["region"] = arguments["--region"].(string)
		encryptParams["keyId"] = arguments["<key_id>"].(string)
	} else if _, exists = arguments["local"]; exists {
		myCrypter = internal.CryptersMap["local"]
	}

	if isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Printf("Enter plaintext: ")
	}
	var plaintext string
	_, err := fmt.Scanln(&plaintext)
	if err != nil {
		fmt.Println("Invalid plaintext input!", err)
		return
	}
	secret, err := encryptSecret(myCrypter, plaintext, encryptParams)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}
	text, err := secret.MarshalText()
	if err != nil {
		fmt.Println("Error marshalling secret to text:", err)
		return
	}

	fmt.Println(string(text))
}
