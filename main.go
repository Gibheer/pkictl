package main

import (
  "fmt"
  "os"
  "path/filepath"

  "github.com/gibheer/pki"
)

var (
  EmptyByteArray = make([]byte, 0)
)

//const (
//  RsaLowerLength = 2048
//  RsaUpperLength = 4096
//  TypeLabelRSA   = "RSA PRIVATE KEY"
//  TypeLabelECDSA = "EC PRIVATE KEY"
//  TypeLabelCSR   = "CERTIFICATE REQUEST"
//  TypeLabelPubKey = "PUBLIC KEY"
//)
//
//var (
//  EcdsaLength = []int{224, 256, 384, 521}
//)
//
func main() {
  if len(os.Args) == 1 {
    crash_with_help(1, "No module selected!")
  }
  switch os.Args[1] {
  case "create-private":   create_private_key()
  case "create-public":    create_public_key()
//  case "create-cert-sign": create_sign_request()
//  case "help":             print_modules()
//  case "info":             info_on_file()
//  case "sign-request":     sign_request()
//  case "sign-input":       sign_input()
//  case "verify-signature": verify_signature()
  default: crash_with_help(1, "Command not supported!")
  }
}

// create a private key
func create_private_key() {
  fs := NewFlags("create-private")
  fs.AddOutput()
  fs.AddPrivateKeyGenerationFlags()
  err := fs.Parse(program_args())
  if err != nil { crash_with_help(1, fmt.Sprintf("%s", err)) }

  var pk pki.Pemmer
  switch fs.Flags.PrivateKeyGenerationFlags.Type {
    case "ecdsa": pk, err = pki.NewPrivateKeyEcdsa(fs.Flags.PrivateKeyGenerationFlags.Curve)
    case "rsa":   pk, err = pki.NewPrivateKeyRsa(fs.Flags.PrivateKeyGenerationFlags.Size)
  }
  if err != nil { crash_with_help(2, fmt.Sprintf("%s", err)) }
  marsh_pem, err := pk.MarshalPem()
  if err != nil { crash_with_help(2, fmt.Sprintf("%s", err)) }
  _, err = marsh_pem.WriteTo(fs.Flags.Output)
  if err != nil { crash_with_help(2, fmt.Sprintf("%s", err)) }
}

// create a public key derived from a private key
func create_public_key() {
  fs := NewFlags("create-public")
  fs.AddPrivateKey()
  fs.AddOutput()
  err := fs.Parse(program_args())
  if err != nil { crash_with_help(1, fmt.Sprintf("%s", err)) }

  var pub_key pki.Pemmer
  pub_key = fs.Flags.PrivateKey.Public()
  marsh_pem, err := pub_key.MarshalPem()
  if err != nil { crash_with_help(2, fmt.Sprintf("%s", err)) }
  _, err = marsh_pem.WriteTo(fs.Flags.Output)
  if err != nil { crash_with_help(2, fmt.Sprintf("%s", err)) }
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
    sign-request      sign a certificate request
    sign-input        sign a message with a private key
    verify-signature  verify a signature
`, filepath.Base(os.Args[0]))
  fmt.Println()
}

// crash and provide a helpful message
func crash_with_help(code int, message string) {
  fmt.Fprintln(os.Stderr, message)
  print_modules()
  os.Exit(code)
}

// return the arguments to the program
func program_args() []string {
  return os.Args[2:]
}
