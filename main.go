package main

import (
  "flag"
  "fmt"
  "io"
  "io/ioutil"
  "os"
  "path/filepath"
  "crypto/elliptic"
  "crypto/ecdsa"
  "crypto/rsa"
  "crypto/x509"
  "crypto/x509/pkix"
  "crypto/rand"
  "encoding/pem"
//  "code.google.com/p/go.crypto/ssh/terminal"
//  "math/big"
//  "time"
)

const (
  RsaLowerLength = 2048
  RsaUpperLength = 4096
  TypeLabelRSA   = "RSA PRIVATE KEY"
  TypeLabelECDSA = "EC PRIVATE KEY"
  TypeLabelCSR   = "CERTIFICATE REQUEST"
)

var (
  EcdsaLength = []int{224, 256, 384, 521}
)

type (
  PrivateKey interface {}

  CreateFlags struct {
    CryptType   string // rsa or ecdsa
    CryptLength int    // the bit length
    Output      string // a path or stream to output the private key to

    output_stream io.WriteCloser // the actual stream to the output
  }

  SignFlags struct {
    PrivateKeyPath string // path to the private key
    Output         string // path where to store the CSR
    BaseAttributes pkix.Name

    private_key PrivateKey
    output_stream io.WriteCloser // the output stream for the CSR
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

// get information on file (private key, sign request, certificate, ...)
func info_on_file() {}
// sign a certificate request to create a new certificate
func sign_request() {}

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

func load_private_key_rsa(block *pem.Block) PrivateKey {
  key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
  if err != nil {
    crash_with_help(3, fmt.Sprintf("Error parsing private key: %s", err))
  }
  return key
}
func load_private_key_ecdsa(block *pem.Block) PrivateKey {
  key, err := x509.ParseECPrivateKey(block.Bytes)
  if err != nil {
    crash_with_help(3, fmt.Sprintf("Error parsing private key: %s", err))
  }
  return key
}

// open stream for given path
func open_output_stream(path string) (io.WriteCloser, error) {
  if path == "STDOUT" {
    return os.Stdout, nil
  } else {
    var err error
    output_stream, err := os.OpenFile(path, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600)
    if err != nil {
      return nil, err
    }
    return output_stream, nil
  }
}

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
