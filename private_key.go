package main

import (
  "crypto"
  "crypto/elliptic"
  "crypto/ecdsa"
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "flag"
  "fmt"
  "io"
  "io/ioutil"
  "os"
)

type (
  PrivateKey interface {
    Public() crypto.PublicKey
  }

  CreateFlags struct {
    CryptType   string // rsa or ecdsa
    CryptLength int    // the bit length
    Output      string // a path or stream to output the private key to

    output_stream io.WriteCloser // the actual stream to the output
  }
)

// create a new private key
func create_private_key() {
  flags := parse_create_flags()

  var err error
  flags.output_stream, err = open_output_stream(flags.Output)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when creating file %s: %s", flags.Output, err))
  }
  defer flags.output_stream.Close()

  switch flags.CryptType {
    case "rsa":   create_private_key_rsa(flags)
    case "ecdsa": create_private_key_ecdsa(flags)
    default: crash_with_help(2, fmt.Sprintf("%s not supported!", flags.CryptType))
  }
}

// generate a rsa private key
func create_private_key_rsa(flags CreateFlags) {
  if flags.CryptLength < 2048 {
    crash_with_help(2, "Length is smaller than 2048!")
  }

  priv, err := rsa.GenerateKey( rand.Reader, flags.CryptLength)
  if err != nil {
    fmt.Fprintln(os.Stderr, "Error: ", err)
    os.Exit(3)
  }
  marshal := x509.MarshalPKCS1PrivateKey(priv)
  block := &pem.Block{Type: TypeLabelRSA, Bytes: marshal}
  pem.Encode(flags.output_stream, block)
}

// generate a ecdsa private key
func create_private_key_ecdsa(flags CreateFlags) {
  var curve elliptic.Curve
  switch flags.CryptLength {
    case 224: curve = elliptic.P224()
    case 256: curve = elliptic.P256()
    case 384: curve = elliptic.P384()
    case 521: curve = elliptic.P521()
    default: crash_with_help(2, "Unsupported crypt length!")
  }

  priv, err := ecdsa.GenerateKey(curve, rand.Reader)
  if err != nil {
    fmt.Fprintln(os.Stderr, "Error: ", err)
    os.Exit(3)
  }
  marshal, err := x509.MarshalECPrivateKey(priv)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Problems marshalling the private key: %s", err))
  }
  block := &pem.Block{Type: TypeLabelECDSA, Bytes: marshal}
  pem.Encode(flags.output_stream, block)
}

// parse the flags to create a private key
func parse_create_flags() CreateFlags {
  flags := CreateFlags{}
  fs := flag.NewFlagSet("create-private", flag.ExitOnError)
  fs.StringVar(&flags.CryptType, "type", "ecdsa", "which type to use to encrypt key (rsa, ecdsa)")
  fs.IntVar(&flags.CryptLength, "length", 521, fmt.Sprintf(
                      "%i - %i for rsa; %v for ecdsa", RsaLowerLength, RsaUpperLength, EcdsaLength,))
  fs.StringVar(&flags.Output, "output", "STDOUT", "filename to store the private key")
  fs.Parse(os.Args[2:])

  return flags
}

// load the private key stored at `path`
func load_private_key(path string) PrivateKey {
  if path == "" {
    crash_with_help(2, "No path to private key supplied!")
  }

  file, err := os.Open(path)
  if err != nil {
    crash_with_help(3, fmt.Sprintf("Error when opening private key: %s", err))
  }
  defer file.Close()

  data, err := ioutil.ReadAll(file)
  if err != nil {
    crash_with_help(3, fmt.Sprintf("Error when reading private key: %s", err))
  }

  block, _ := pem.Decode(data)
  if block.Type == TypeLabelRSA {
    return load_private_key_rsa(block)
  } else if block.Type == TypeLabelECDSA {
    return load_private_key_ecdsa(block)
  } else {
    crash_with_help(2, "No valid private key file! Only RSA and ECDSA keys are allowed!")
    return nil
  }
}

// parse rsa private key
func load_private_key_rsa(block *pem.Block) PrivateKey {
  key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
  if err != nil {
    crash_with_help(3, fmt.Sprintf("Error parsing private key: %s", err))
  }
  return key
}

// parse ecdsa private key
func load_private_key_ecdsa(block *pem.Block) PrivateKey {
  key, err := x509.ParseECPrivateKey(block.Bytes)
  if err != nil {
    crash_with_help(3, fmt.Sprintf("Error parsing private key: %s", err))
  }
  return key
}
