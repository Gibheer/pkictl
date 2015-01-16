package main

import (
  "crypto"
  "crypto/rand"
  "crypto/sha256"
  "errors"
  "flag"
  "fmt"
  "io"
  "os"
//  "crypto/ecdsa"
//  "crypto/rsa"
)

type (
  SignInputFlags struct {
    Message        string // the message to sign
    PrivateKeyPath string // path to the private key
    Output         string // a path or stream to output the private key to

    private_key crypto.Signer
    output_stream io.Writer // the output stream for the CSR
  }
)

func sign_input() {
  flags := parse_sign_input_flags()
  flags.private_key = load_private_key(flags.PrivateKeyPath)

  output_stream, err := open_output_stream(flags.Output)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when creating file %s: %s", flags.Output, err))
  }
  flags.output_stream = output_stream
  defer output_stream.Close()

  if err := create_signature(flags); err != nil {
    fmt.Fprintln(os.Stderr, "Error when creating signature", err)
    os.Exit(3)
  }
}

func parse_sign_input_flags() SignInputFlags {
  flags := SignInputFlags{}
  fs := flag.NewFlagSet("sign-input", flag.ExitOnError)
  fs.StringVar(&flags.PrivateKeyPath, "private-key", "", "path to the private key file")
  fs.StringVar(&flags.Output, "output", "STDOUT", "path where the generated signature should be stored")
  fs.StringVar(&flags.Message, "message", "", "the message to sign")
  fs.Parse(os.Args[2:])

  return flags
}

func create_signature(flags SignInputFlags) error {
  message := []byte(flags.Message)
  // compute sha256 of the message
  hash := sha256.New()
  length, _ := hash.Write(message)
  if length != len(message) { return errors.New("Error when creating hash over message!") }
  fmt.Println(hash.Sum(nil))

  // create signature of the hash using the private key
  signature, err := flags.private_key.Sign(
    rand.Reader,
    hash.Sum([]byte("")),
    nil,
  )
  if err != nil { return err }
  fmt.Println(signature)
  flags.output_stream.Write(signature)
  return nil
}
