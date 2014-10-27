package main

import (
  "flag"
  "fmt"
  "io"
  "os"
  "path/filepath"
  "crypto/elliptic"
  "crypto/ecdsa"
  "crypto/rsa"
  "crypto/x509"
//  "crypto/x509/pkix"
  "crypto/rand"
  "encoding/pem"
//  "code.google.com/p/go.crypto/ssh/terminal"
//  "math/big"
//  "time"
)

const (
  RsaLowerLength = 2048
  RsaUpperLength = 4096
)

var (
  EcdsaLength = []int{224, 256, 384, 521}
)

type (
  CreateFlags struct {
    CryptType   string // rsa or ecdsa
    CryptLength int    // the bit length
    Output      string // a path or stream to output the private key to

    output_stream io.WriteCloser // the actual stream to the output
  }
)

func main() {
  if len(os.Args) == 1 {
    crash_with_help(1, "No module selected!")
  }
  switch os.Args[1] {
  case "create-private": create_private_key()
  case "create-cert-sign": create_sign_request()
  case "help": print_modules()
  case "info": info_on_file()
  case "sign": sign_request()
  }
}

// create a new private key
func create_private_key() {
  flags := parse_create_flags()

  if flags.Output == "STDOUT" {
    flags.output_stream = os.Stdout
  } else {
    var err error
    flags.output_stream, err = os.OpenFile(flags.Output, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600)
    if err != nil {
      crash_with_help(2, fmt.Sprintf("Error when creating file %s: %s", flags.Output, err))
    }
    defer flags.output_stream.Close()
  }

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
  block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: marshal}
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
  block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: marshal}
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

// create a sign request with a private key
func create_sign_request() {}
// get information on file (private key, sign request, certificate, ...)
func info_on_file() {}
// sign a certificate request to create a new certificate
func sign_request() {}

// print the module help
func print_modules() {
  fmt.Printf(`Usage: %s command args
where 'command' is one of:
    create-private    create a new private key
    create-cert-sign  create a new certificate sign request
    help              show this help
    info              get info on a file
    sign              sign a certificate request
`, filepath.Base(os.Args[0]))
  fmt.Println()
}

func crash_with_help(code int, message string) {
  fmt.Fprintln(os.Stderr, message)
  print_modules()
  os.Exit(code)
}

//  fmt.Println("Lets create a cert!")
//  template := &x509.Certificate{
//    SerialNumber:  big.NewInt(1),
//    Subject: pkix.Name{
//      Organization: []string{"Acme Co"},
//    },
//    NotBefore: time.Now(),
//    NotAfter: time.Now().Add(365 * 24 * time.Hour),
//    KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
//    ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
//    BasicConstraintsValid: true,
//  }
//  priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
//  fmt.Println(priv.PublicKey, err)
//  raw_string, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
//  cert, err := x509.ParseCertificate(raw_string)
//  fmt.Println(cert, err)
//
//  // read a password or so
//  password, err := terminal.ReadPassword(0)
//  fmt.Println(string(password), err)
//}
