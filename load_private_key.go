package main

import (
	"fmt"
	"os"

	"github.com/gibheer/pki"
)

func loadPrivateKey(path string) (pki.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("no path given")
	}
	var err error
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm().String()[4:] != "------" {
		return nil, fmt.Errorf("private key must not be readable for group or world")
	}

	pems, err := parseFile(file)
	if err != nil {
		return nil, err
	}
	if len(pems) > 1 {
		return nil, fmt.Errorf("more than one object in file")
	}

	var pk pki.PrivateKey
	for key, parts := range pems {
		if len(parts) > 1 {
			return nil, fmt.Errorf("more than one object found")
		}
		switch key {
		case pki.PemLabelRsa:
			pk, err = pki.LoadPrivateKeyRsa(parts[0])
		case pki.PemLabelEd25519:
			pk, err = pki.LoadPrivateKeyEd25519(parts[0])
		case pki.PemLabelEcdsa:
			pk, err = pki.LoadPrivateKeyEcdsa(parts[0])
		default:
			return nil, fmt.Errorf("unknown private key format %s", key)
		}
	}
	return pk, err
}
