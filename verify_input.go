package main

import (
	"crypto"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/gibheer/pki"
)

func VerifyInput(args []string) error {
	fs := flag.NewFlagSet("pkictl verify-input", flag.ExitOnError)
	flagPublic := fs.String("public-key", "", "path to the public key or read from stdin")
	flagInput := fs.String("input", "stdin", "path to the message or stdin")
	flagSignature := fs.String("signature", "", "the signature to check the message against")
	fs.Parse(args)

	sig, err := base64.StdEncoding.DecodeString(*flagSignature)
	if err != nil {
		return err
	}

	in, err := openInput(*flagInput)
	if err != nil {
		return err
	}
	defer in.Close()
	msg, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}

	pub_raw, err := openInput(*flagPublic)
	if err != nil {
		return err
	}
	defer pub_raw.Close()
	pem, err := parseFile(pub_raw)
	if err != nil {
		return err
	}
	if len(pem) > 1 {
		return fmt.Errorf("too many objects in public key file")
	}
	if len(pem[pki.PemLabelPublic]) > 1 {
		return fmt.Errorf("too many public keys found")
	}

	public, err := loadPublicKey(pem[pki.PemLabelPublic][0])
	if err != nil {
		return err
	}

	valid, err := public.Verify(msg, sig, crypto.SHA256)
	if valid {
		fmt.Println("valid")
		return nil
	}
	fmt.Println("invalid")
	return err
}

func loadPublicKey(raw_pu []byte) (pki.PublicKey, error) {
	if public, err := pki.LoadPublicKeyEd25519(raw_pu); err != nil {
		return public, nil
	}
	if public, err := pki.LoadPublicKeyEcdsa(raw_pu); err == nil {
		return public, nil
	}
	if public, err := pki.LoadPublicKeyRsa(raw_pu); err == nil {
		return public, nil
	}
	return nil, fmt.Errorf("no valid public key found")
}
