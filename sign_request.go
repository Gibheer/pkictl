package main

import (
  "crypto/rand"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
  "fmt"
  "flag"
  "io"
  "os"
)

type (
  SignFlags struct {
    PrivateKeyPath string // path to the private key
    Output         string // path where to store the CSR
    BaseAttributes pkix.Name

    private_key PrivateKey
    output_stream io.WriteCloser // the output stream for the CSR
  }
)

// create a sign request with a private key
func create_sign_request() {
  flags := parse_sign_flags()
  flags.private_key = load_private_key(flags.PrivateKeyPath)

  var err error
  flags.output_stream, err = open_output_stream(flags.Output)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when creating file %s: %s", flags.Output, err))
  }
  defer flags.output_stream.Close()

  csr_template := &x509.CertificateRequest{
    Subject: flags.BaseAttributes,
  }
  csr_raw, err := x509.CreateCertificateRequest(rand.Reader, csr_template, flags.private_key)
  if err != nil {
    fmt.Fprintln(os.Stderr, "Error when generating CSR: ", err)
    os.Exit(3)
  }
  block := &pem.Block{Type: TypeLabelCSR, Bytes: csr_raw}
  pem.Encode(flags.output_stream, block)
}

// parse the flags to create a certificate sign request
func parse_sign_flags() SignFlags {
  flags := SignFlags{}
  fs := flag.NewFlagSet("create-cert-sign", flag.ExitOnError)
  fs.StringVar(&flags.PrivateKeyPath, "private-key", "", "path to the private key file")
  fs.StringVar(&flags.Output, "output", "STDOUT", "path where the generated csr should be stored")

  flags.BaseAttributes = pkix.Name{}
  fs.StringVar(&flags.BaseAttributes.CommonName, "common-name", "", "the name of the resource")
  fs.StringVar(&flags.BaseAttributes.SerialNumber, "serial", "1", "serial number for the request")

  fs.Parse(os.Args[2:])
  return flags
}
