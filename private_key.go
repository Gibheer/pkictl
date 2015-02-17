package main

import (
  "errors"
  "github.com/gibheer/pki"
)

const (
  TypeLabelRSA   = "RSA PRIVATE KEY"
  TypeLabelECDSA = "EC PRIVATE KEY"
)

var (
  ErrNoPKFound = errors.New("no private key found")
)

// Read the private key from the path and try to figure out which type of key it
// might be.
func ReadPrivateKeyFile(path string) (pki.PrivateKey, error) {
  raw_pk, err := readSectionFromFile(path, TypeLabelECDSA)
  if err == nil {
    pk, err := pki.LoadPrivateKeyEcdsa(raw_pk)
    if err != nil { return nil, err }
    return pk, nil
  }
  raw_pk, err = readSectionFromFile(path, TypeLabelRSA)
  if err == nil {
    pk, err := pki.LoadPrivateKeyRsa(raw_pk)
    if err != nil { return nil, err }
    return pk, nil
  }
  return nil, ErrNoPKFound
}
