package main

import (
  "crypto/x509"
  "encoding/pem"
  "flag"
  "fmt"
  "io"
  "os"
)

type (
  PublicKeyFlags struct {
    PrivateKeyPath string
    Output         string

    output_stream io.WriteCloser // the actual stream to the output
  }
)

func create_public_key() {
  var err error
  flags := parse_public_key_flags()
  flags.output_stream, err = open_output_stream(flags.Output)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when creating file %s: %s", flags.Output, err))
  }
  defer flags.output_stream.Close()

  priv_key := load_private_key(flags.PrivateKeyPath)
  marshal, err := x509.MarshalPKIXPublicKey(priv_key.Public())
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Problems marshalling the public key: %s", err))
  }

  block := &pem.Block{Type: TypeLabelPubKey, Bytes: marshal}
  pem.Encode(flags.output_stream, block)
}

func parse_public_key_flags() PublicKeyFlags {
  flags := PublicKeyFlags{}
  fs := flag.NewFlagSet("create-public", flag.ExitOnError)
  fs.StringVar(&flags.PrivateKeyPath, "private-key", "", "path to the private key file")
  fs.StringVar(&flags.Output, "output", "STDOUT", "path where the generated public key should be stored")
  fs.Parse(os.Args[2:])

  return flags
}
