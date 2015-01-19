package main

import (
  "fmt"
  "io"
  "os"
  "path/filepath"
)

const (
  RsaLowerLength = 2048
  RsaUpperLength = 4096
  TypeLabelRSA   = "RSA PRIVATE KEY"
  TypeLabelECDSA = "EC PRIVATE KEY"
  TypeLabelCSR   = "CERTIFICATE REQUEST"
  TypeLabelPubKey = "PUBLIC KEY"
)

var (
  EcdsaLength = []int{224, 256, 384, 521}
)

func main() {
  if len(os.Args) == 1 {
    crash_with_help(1, "No module selected!")
  }
  switch os.Args[1] {
  case "create-private":   create_private_key()
  case "create-cert-sign": create_sign_request()
  case "create-public":    create_public_key()
  case "help":             print_modules()
  case "info":             info_on_file()
  case "sign-request":     sign_request()
  case "sign-input":       sign_input()
  case "verify-signature": verify_signature()
  default: crash_with_help(1, "Command not supported!")
  }
}

// get information on file (private key, sign request, certificate, ...)
func info_on_file() {}
// sign a certificate request to create a new certificate
func sign_request() {}

// open stream for given path
func open_output_stream(path string) (io.WriteCloser, error) {
  switch path {
  case "STDOUT": return os.Stdout, nil
  case "STDERR": return os.Stderr, nil
  default: return open_stream(path, os.O_WRONLY | os.O_CREATE | os.O_TRUNC)
  }
}

func open_input_stream(path string) (io.ReadCloser, error) {
  switch path {
  case "STDIN": return os.Stdin, nil
  default: return open_stream(path, os.O_RDONLY)
  }
}

func open_stream(path string, flags int) (io.ReadWriteCloser, error) {
  var err error
  output_stream, err := os.OpenFile(path, flags, 0600)
  if err != nil {
    return nil, err
  }
  return output_stream, nil
}

// print the module help
func print_modules() {
  fmt.Printf(`Usage: %s command args
where 'command' is one of:
    create-private    create a new private key
    create-public     create a public key from a private one
    create-cert-sign  create a new certificate sign request
    help              show this help
    info              get info on a file
    sign              sign a certificate request
    sign-input        sign a message with a private key
    verify-signature  verify a signature
`, filepath.Base(os.Args[0]))
  fmt.Println()
}

func crash_with_help(code int, message string) {
  fmt.Fprintln(os.Stderr, message)
  print_modules()
  os.Exit(code)
}
