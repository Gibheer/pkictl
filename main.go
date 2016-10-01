// This package builds a binary which helps to generate
// private keys, public keys, certificates and also
// includes functionality to sign and verify messages.
package main

import (
	"fmt"
	"os"
)

const (
	COMMAND = "pkictl"
)

func main() {
	if len(os.Args) == 1 {
		printHelp()
		return
	}
	command, args := os.Args[1], os.Args[2:]
	var err error
	switch command {
	case "create-private":
		err = CreatePrivateKey(args)
	case "create-public":
		err = CreatePublicKey(args)
	case "sign-input":
		err = SignInput(args)
	case "verify-input":
		err = VerifyInput(args)
	case "create-sign-request":
		err = CreateSignRequest(args)
	case "create-cert":
		err = CreateCert(args)
	default:
		printHelp()
	}
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(2)
	}
}

func printHelp() {
	fmt.Printf(`Usage: %s command [flags]

where 'command' is one of:
  create-private        create a private key
  create-public         create a public key derived from a private key
  sign-input            sign a message using a private key
  verify-input          verify a message using a signature and a public key
  create-sign-request   create a certificate sign request
  create-cert           create a certificate from a certificate sign request
  diff                  show the differences between two certificates
`, COMMAND)
}
