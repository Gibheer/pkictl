package main

import (
	"flag"
)

func CreatePublicKey(args []string) error {
	fs := flag.NewFlagSet("pkictl create-public-key", flag.ExitOnError)
	flagPrivate := fs.String("private-key", "", "path to the private key or read from stdin")
	flagOutput := fs.String("output", "stdout", "write private key to file")
	fs.Parse(args)

	pk, err := loadPrivateKey(*flagPrivate)
	if err != nil {
		return err
	}

	out, err := openOutput(*flagOutput)
	if err != nil {
		return err
	}
	defer out.Close()

	pub := pk.Public()
	return writePem(pub, out)
}
