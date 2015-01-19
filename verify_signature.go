package main

import (
  "crypto/ecdsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/asn1"
  "encoding/pem"
  "encoding/base64"
  "errors"
  "flag"
  "fmt"
  "io"
  "io/ioutil"
  "math/big"
  "os"
  "strings"
)

type (
  VerifySignatureFlags struct {
    Message        string // the message to sign
    MessageStream  string // the path to the input stream
    PublicKeyPath  string // path to the private key
    Signature      string // a path or stream to output the private key to
    SignatureStream string // read signature from an input stream
    Format         string // the format of the signature

    message_stream   io.Reader // the message stream
    signature_stream io.Reader // the signature stream
  }
  // struct to load the signature into (which is basically two bigint in byte form)
  Signature struct {
    R, S *big.Int
  }
)

func verify_signature() {
  flags := parse_verify_signature_flags()
  if flags.SignatureStream == flags.MessageStream &&
     ( flags.Message == "" && flags.Signature == "") {
    crash_with_help(2, "Signature and Message stream can't be the same source!")
  }

  // open streams
  if flags.Message == "" && flags.MessageStream != "" {
    message_stream, err := open_input_stream(flags.MessageStream)
    if err != nil {
      crash_with_help(2, fmt.Sprintf("Error when opening stream %s: %s", flags.MessageStream, err))
    }
    defer message_stream.Close()
    flags.message_stream = message_stream
  }
  if flags.Signature == "" && flags.SignatureStream != "" {
    signature_stream, err := open_input_stream(flags.SignatureStream)
    if err != nil {
      crash_with_help(2, fmt.Sprintf("Error when opening stream %s: %s", flags.SignatureStream, err))
    }
    defer signature_stream.Close()
    flags.signature_stream = signature_stream
  }

  public_key, err := load_public_key_ecdsa(flags.PublicKeyPath)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when loading public key: %s", err))
  }
  signature, err := load_signature(flags)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when loading the signature: %s", err))
  }
  message, err := load_message(flags)
  hash := sha256.New()
  hash.Write([]byte(message))

  success := ecdsa.Verify(public_key, hash.Sum(nil), signature.R, signature.S)
  fmt.Println(success)
}

// parse the parameters
func parse_verify_signature_flags() VerifySignatureFlags {
  flags := VerifySignatureFlags{}
  fs := flag.NewFlagSet("verify-signature", flag.ExitOnError)
  fs.StringVar(&flags.PublicKeyPath, "public-key", "", "path to the public key file")
  fs.StringVar(&flags.Signature, "signature", "", "path where the signature file can be found")
  fs.StringVar(&flags.SignatureStream, "signature-stream", "", "the path to the stream of the signature (file, STDIN)")
  fs.StringVar(&flags.Format, "format", "auto", "the input format of the signature (auto, binary, base64)")
  fs.StringVar(&flags.Message, "message", "", "the message to validate")
  fs.StringVar(&flags.MessageStream, "message-stream", "STDIN", "the path to the stream to validate (file, STDIN)")
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
func load_signature(flags VerifySignatureFlags) (*Signature, error) {
  var signature_raw []byte
  var err error
  if flags.Message != "" {
    signature_raw = []byte(flags.Message)
  } else {
    signature_raw, err = ioutil.ReadAll(flags.signature_stream)
    if err != nil { return nil, err }
  }

  switch strings.ToLower(flags.Format) {
  case "auto":
    sig, err := load_signature_base64(signature_raw)
    if err != nil {
      sig, err = load_signature_binary(signature_raw)
      if err != nil { return nil, err }
      return sig, nil
    }
    return sig, nil
  case "base64": return load_signature_base64(signature_raw)
  case "binary": return load_signature_binary(signature_raw)
  default: return nil, errors.New("Unknown format!")
  }
}

// convert the signature from base64 into a signature
func load_signature_base64(signature_raw []byte) (*Signature, error) {
  asn1_sig, err := base64.StdEncoding.DecodeString(string(signature_raw))
  if err != nil { return nil, err }
  return load_signature_binary(asn1_sig)
}

// convert the signature from asn1 into a signature
func load_signature_binary(signature_raw []byte) (*Signature, error) {
  var signature Signature
  _, err := asn1.Unmarshal(signature_raw, &signature)
  if err != nil { return nil, err }
  return &signature, nil
}

// load the message from a stream or the parameter
func load_message(flags VerifySignatureFlags) (string, error) {
  if flags.Message != "" { return flags.Message, nil }
  message, err := ioutil.ReadAll(flags.message_stream)
  if err != nil { return "", err }
  return string(message), nil
}
