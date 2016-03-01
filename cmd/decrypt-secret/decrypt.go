package main

import (
	"fmt"

	"github.com/Zemanta/go-secretcrypt"
	"github.com/docopt/docopt-go"
)

func decryptSecret(secretStr string) {
	secret, err := secretcrypt.LoadStrictSecret(secretStr)
	if err != nil {
		fmt.Println("Error parsing secret:", err)
		return
	}
	plaintext, err := secret.Decrypt()
	if err != nil {
		fmt.Println("Error decrypting secret", secretStr, ", err:", err)
		return
	}
	fmt.Println(plaintext)
}

func main() {
	usage := `Encrypted secrets.

Usage:
  decrypt-secret <secret>
`
	arguments, _ := docopt.Parse(usage, nil, true, "0.1", false)
	decryptSecret(arguments["<secret>"].(string))
}
