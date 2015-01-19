package main

import (
  "crypto"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "errors"
  "flag"
  "fmt"
  "io"
  "io/ioutil"
  "os"
//  "crypto/ecdsa"
//  "crypto/rsa"
)

type (
  SignInputFlags struct {
    Message        string // the message to sign
    MessageStream  string // the message stream to sign
    PrivateKeyPath string // path to the private key
    Output         string // a path or stream to output the private key to
    Format         string // the format of the output

    private_key crypto.Signer
    output_stream io.Writer // the output stream for the CSR
    input_stream  io.Reader // the input stream to read the message from
  }
)

func sign_input() {
  flags := parse_sign_input_flags()
  if flags.Message != "" && flags.MessageStream != "" {
    crash_with_help(2, "Only message or message file can be signed!")
  }
  flags.private_key = load_private_key(flags.PrivateKeyPath)

  output_stream, err := open_output_stream(flags.Output)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when creating file %s: %s", flags.Output, err))
  }
  flags.output_stream = output_stream
  defer output_stream.Close()

  if flags.MessageStream != "" {
    input_stream, err := open_input_stream(flags.MessageStream)
    if err != nil {
      crash_with_help(2, fmt.Sprintf("Error when opening stream %s: %s", flags.MessageStream, err))
    }
    flags.input_stream = input_stream
    defer input_stream.Close()
  }

  if err := create_signature(flags); err != nil {
    fmt.Fprintln(os.Stderr, "Error when creating signature", err)
    os.Exit(3)
  }
}

func parse_sign_input_flags() SignInputFlags {
  flags := SignInputFlags{}
  fs := flag.NewFlagSet("sign-input", flag.ExitOnError)
  fs.StringVar(&flags.PrivateKeyPath, "private-key", "", "path to the private key file")
  fs.StringVar(&flags.Output, "output", "STDOUT", "path where the generated signature should be stored (STDOUT, STDERR, file)")
  fs.StringVar(&flags.Message, "message", "", "the message to sign")
  fs.StringVar(&flags.MessageStream, "message-stream", "STDIN", "the path to the stream to sign (file, STDIN)")
  fs.StringVar(&flags.Format, "format", "base64", "the output format (binary, base64)")
  fs.Parse(os.Args[2:])

  return flags
}

func create_signature(flags SignInputFlags) error {
  var message []byte
  var err error

  if flags.MessageStream != "" {
    message, err = ioutil.ReadAll(flags.input_stream)
    if err != nil { return err }
  } else {
    message = []byte(flags.Message)
  }
  // compute sha256 of the message
  hash := sha256.New()
  length, _ := hash.Write(message)
  if length != len(message) { return errors.New("Error when creating hash over message!") }

  // create signature of the hash using the private key
  signature, err := flags.private_key.Sign(
    rand.Reader,
    hash.Sum([]byte("")),
    nil,
  )
  if err != nil { return err }
  if flags.Format == "base64" {
    flags.output_stream.Write([]byte(base64.StdEncoding.EncodeToString(signature)))
  } else {
    flags.output_stream.Write(signature)
  }
  flags.output_stream.Write([]byte("\n"))
  return nil
}
