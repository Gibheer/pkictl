package main

import (
	"crypto"
	"encoding/base64"
	"flag"
	"io"
	"io/ioutil"
)

func SignInput(args []string) error {
	fs := flag.NewFlagSet("pkictl sign-input", flag.ExitOnError)
	flagPrivate := fs.String("private-key", "", "path to the private key or read from stdin")
	flagInput := fs.String("input", "stdin", "path to the message to sign or stdin")
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

	in, err := openInput(*flagInput)
	if err != nil {
		return err
	}
	defer in.Close()

	message, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}

	signature, err := pk.Sign(message, crypto.SHA256)
	if err != nil {
		return err
	}

	_, err = io.WriteString(out, base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		return err
	}
	return nil
}
