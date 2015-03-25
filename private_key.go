package main

import (
	"errors"
	"github.com/gibheer/pki"
)

var (
	ErrNoPKFound     = errors.New("no private key found")
	ErrNoPUFound     = errors.New("no public key found")
	ErrUnknownFormat = errors.New("key is an unknown format")
)

// Read the private key from the path and try to figure out which type of key it
// might be.
func ReadPrivateKeyFile(path string) (pki.PrivateKey, error) {
	raw_pk, err := readSectionFromFile(path, pki.PemLabelEcdsa)
	if err == nil {
		pk, err := pki.LoadPrivateKeyEcdsa(raw_pk)
		if err != nil {
			return nil, err
		}
		return pk, nil
	}
	raw_pk, err = readSectionFromFile(path, pki.PemLabelRsa)
	if err == nil {
		pk, err := pki.LoadPrivateKeyRsa(raw_pk)
		if err != nil {
			return nil, err
		}
		return pk, nil
	}
	return nil, ErrNoPKFound
}

// read the public key and try to figure out what kind of key it might be
func ReadPublicKeyFile(path string) (pki.PublicKey, error) {
	raw_pu, err := readSectionFromFile(path, pki.PemLabelPublic)
	if err != nil {
		return nil, ErrNoPUFound
	}

	var public pki.PublicKey
	public, err = pki.LoadPublicKeyEcdsa(raw_pu)
	if err == nil {
		return public, nil
	}
	public, err = pki.LoadPublicKeyRsa(raw_pu)
	if err == nil {
		return public, nil
	}
	return nil, ErrUnknownFormat
}
