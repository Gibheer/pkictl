package main

import (
  "crypto/ecdsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/asn1"
  "encoding/pem"
  "errors"
  "flag"
  "fmt"
  "io/ioutil"
  "math/big"
  "os"
)

type (
  VerifySignatureFlags struct {
    Message        string // the message to sign
    PublicKeyPath  string // path to the private key
    Signature      string // a path or stream to output the private key to
  }
  // struct to load the signature into (which is basically two bigint in byte form)
  Signature struct {
    R, S *big.Int
  }
)

func verify_signature() {
  flags := parse_verify_signature_flags()
  public_key, err := load_public_key_ecdsa(flags.PublicKeyPath)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when loading public key: %s", err))
  }
  signature, err := load_signature(flags.Signature)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when loading the signature: %s", err))
  }
  hash := sha256.New()
  hash.Write([]byte(flags.Message))

  success := ecdsa.Verify(public_key, hash.Sum(nil), signature.R, signature.S)
  fmt.Println(success)
}

// parse the parameters
func parse_verify_signature_flags() VerifySignatureFlags {
  flags := VerifySignatureFlags{}
  fs := flag.NewFlagSet("verify-signature", flag.ExitOnError)
  fs.StringVar(&flags.PublicKeyPath, "public-key", "", "path to the public key file")
  fs.StringVar(&flags.Signature, "signature", "", "path where the signature file can be found")
  fs.StringVar(&flags.Message, "message", "", "the message to be validated")
  fs.Parse(os.Args[2:])

  return flags
}

// load the private key from pem file
func load_public_key_ecdsa(path string) (*ecdsa.PublicKey, error) {
  public_key_file, err := os.Open(path)
  if err != nil { return nil, err }
  public_key_pem, err := ioutil.ReadAll(public_key_file)
  if err != nil { return nil, err }
  public_key_file.Close()

  block, _ := pem.Decode(public_key_pem)
  if block.Type != TypeLabelPubKey {
    return nil, errors.New(fmt.Sprintf("No public key found in %s", path))
  }

  public_key, err := x509.ParsePKIXPublicKey(block.Bytes)
  if err != nil { return nil, err }
  return public_key.(*ecdsa.PublicKey), nil
}

// parse the signature from asn1 file
func load_signature(path string) (*Signature, error) {
  signature_file, err := os.Open(path)
  if err != nil { return nil, err }
  signature_raw, err := ioutil.ReadAll(signature_file)
  if err != nil { return nil, err }
  signature_file.Close()

  var signature Signature
  _, err = asn1.Unmarshal(signature_raw, &signature)
  if err != nil { return nil, err }
  return &signature, nil
}
