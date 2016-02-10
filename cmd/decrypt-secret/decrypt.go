package main

import (
	"fmt"

	"github.com/Zemanta/go-secretcrypt/internal"
	"github.com/docopt/docopt-go"
)

func main() {
	usage := `Encrypted secrets.

Usage:
  decrypt-secret <secret>
`
	arguments, _ := docopt.Parse(usage, nil, true, "0.1", false)
	secret, err := internal.NewSecretFromString(arguments["<secret>"].(string))
	if err != nil {
		fmt.Println("Error parsing secret:", err)
		return
	}
	plaintext, err := secret.Decrypt()
	if err != nil {
		fmt.Println("Error decrypting secret", arguments["<secret>"], ", err:", err)
		return
	}
	fmt.Println(plaintext)
}
