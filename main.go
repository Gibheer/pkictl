package main

import (
  "crypto"
  "encoding/base64"
  "fmt"
  "io"
  "io/ioutil"
  "os"
  "path/filepath"

  "github.com/gibheer/pki"
)

var (
  EmptyByteArray = make([]byte, 0)
)

func main() {
  if len(os.Args) == 1 {
    crash_with_help(1, "No module selected!")
  }
  switch os.Args[1] {
  case "create-private":   create_private_key()
  case "create-public":    create_public_key()
  case "sign-input":       sign_input()
//  case "verify-signature": verify_signature()
//  case "create-cert-sign": create_sign_request()
//  case "sign-request":     sign_request()
  case "help":             print_modules()
//  case "info":             info_on_file()
  default: crash_with_help(1, "Command not supported!")
  }
}

// create a private key
func create_private_key() {
  fs := NewFlags("create-private")
  fs.AddOutput()
  fs.AddPrivateKeyGenerationFlags()
  err := fs.Parse(program_args())
  if err != nil { os.Exit(2) }

  var pk pki.Pemmer
  switch fs.Flags.PrivateKeyGenerationFlags.Type {
    case "ecdsa": pk, err = pki.NewPrivateKeyEcdsa(fs.Flags.PrivateKeyGenerationFlags.Curve)
    case "rsa":   pk, err = pki.NewPrivateKeyRsa(fs.Flags.PrivateKeyGenerationFlags.Size)
  }
  if err != nil { os.Exit(2) }
  marsh_pem, err := pk.MarshalPem()
  if err != nil { os.Exit(2) }
  _, err = marsh_pem.WriteTo(fs.Flags.Output)
  if err != nil { os.Exit(2) }
}

// create a public key derived from a private key
func create_public_key() {
  fs := NewFlags("create-public")
  fs.AddPrivateKey()
  fs.AddOutput()
  err := fs.Parse(program_args())
  if err != nil { os.Exit(2) }

  var pub_key pki.Pemmer
  pub_key = fs.Flags.PrivateKey.Public()
  marsh_pem, err := pub_key.MarshalPem()
  if err != nil { os.Exit(2) }
  _, err = marsh_pem.WriteTo(fs.Flags.Output)
  if err != nil { os.Exit(2) }
}

func sign_input() {
  fs := NewFlags("sign-input")
  fs.AddPrivateKey()
  fs.AddOutput()
  fs.AddInput()
  err := fs.Parse(program_args())
  if err != nil { os.Exit(2) }

  message, err := ioutil.ReadAll(fs.Flags.Input)
  if err != nil { crash_with_help(2, "Error reading input: %s", err) }
  signature, err := fs.Flags.PrivateKey.Sign(message, crypto.SHA256)
  if err != nil { crash_with_help(2, "Could not compute signature: %s", err) }
  _, err = io.WriteString(fs.Flags.Output, base64.StdEncoding.EncodeToString(signature))
  if err != nil { crash_with_help(2, "Could not write to output: %s", err) }

  // if we print to stderr, send a final line break to make the output nice
  if fs.Flags.Output == os.Stdout {
    // we can ignore the result, as either Stdout did work or not
    _, _ = io.WriteString(fs.Flags.Output, "\n")
  }
}

// print the module help
func print_modules() {
  fmt.Printf(`Usage: %s command args
where 'command' is one of:
    create-private    create a new private key
    create-public     create a public key from a private one
    sign-input        sign a message with a private key
    verify-signature  verify a signature
    create-cert-sign  create a new certificate sign request
    sign-request      sign a certificate request
    help              show this help
    info              get info on a file
`, filepath.Base(os.Args[0]))
  fmt.Println()
}

// crash and provide a helpful message
func crash_with_help(code int, message string, args ...interface{}) {
  fmt.Fprintln(os.Stderr, message)
  print_modules()
  os.Exit(code)
}

// return the arguments to the program
func program_args() []string {
  return os.Args[2:]
}
