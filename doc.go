/*
Package secretcrypt is an utility for keeping your secrets encrypted.

For example, you have the following TOML (or any format whose decoder
supports TextUnmarshaler interface for custom values) configuration file

  MySecret = "VerySecretValue!"

but you can't include that file in VCS because then your secret value
would be exposed.

With secretcrypt, you can encrypt your secret using your AWS KMS master
key aliased MyKey:

  $ encrypt-secret kms alias/MyKey
  Enter plaintext: VerySecretValue! # enter
  kms:region=us-east-1:CiC/SXeuXDGRADRIjc0qcE... # shortened for brevity

  # --- or --
  $ echo "VerySecretValue!" | encrypt-secret kms alias/MyKey
  kms:region=us-east-1:CiC/SXeuXDGRADRIjc0qcE... # shortened for brevity
  # only use piping when scripting, otherwise your secrets will be stored
  # in your shell's history!

use that secret in my TOML config file:

  MySecret = "kms:region=us-east-1:CiC/SXeuXDGRADRIjc0qcE..."  # shortened for brevity

or YAML:
  mysecret: kms:region=us-east-1:CiC/SXeuXDGRADRIjc0qcE...  # shortened for brevity

or JSON:
   {"MySecret": "kms:region=us-east-1:CiC/SXeuXDGRADRIjc0qcE..."}

Then, you can use that secret in your config struct

  type Config struct {
    MySecret secretcrypt.Secret
  }

  var conf Config
  if _, err := toml.Decode(tomlData, &conf); err != nil {
    // handle error
  }

and get its plaintext as

  plaintext, err := conf.MySecret.Decrypt()
  if err != nil {
    // handle error
  }

KMS

The KMS option uses AWS Key Management Service. When encrypting and
decrypting KMS secrets, you need to provide which AWS region the is to be or was
encrypted on, but it defaults to us-east-1.

So if you use a custom region, you must provide it to secretcrypt:

  encrypt-secret kms --region us-west-1 alias/MyKey


Local encryption

This mode is meant for local and/or offline development usage.
It generates a local key in your user data dir
(see appdirs at https://pypi.python.org/pypi/appdirs/1.4.0), so that the key cannot
be accidentally committed to CVS.

It then uses that key to symmetrically encrypt and decrypt your secrets.
*/
package secretcrypt
