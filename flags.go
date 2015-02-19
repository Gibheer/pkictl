package main

// This file handles the complete parameter assignment, as some parameters are
// often used by multiple functions.

import (
  "crypto/elliptic"
  "flag"
  "fmt"
  "io"
  "os"

  "github.com/gibheer/pki"
)

const (
  RsaLowerLength = 2048
  RsaUpperLength = 16384
)

var (
  EcdsaCurves    = []int{224, 256, 384, 521}
)

type (
  // holds all certificate related flags, which need parsing afterwards
  certFlagsContainer struct {
    serialNumber int    // the serial number for the cert
    commonName   string // the common name used in the cert
    dnsNames     string // all alternative names in the certificate (comma separated list)
    ipAddresses  string // all IP addresses in the certificate (comma separated list)
    country      string // the country names which should end up in the cert (comma separated list)
    organization string // the organization names (comma separated list)
    organizationalUnit string // the organizational units (comma separated list)
    locality     string // the city or locality (comma separated list)
    province     string // the province name (comma separated list)
    streetAddress string // the street addresses of the organization (comma separated list)
    postalCode   string // the postal codes of the locality
  }

  // a container go gather all incoming flags for further processing
  paramContainer struct {
    outputPath       string // path to output whatever is generated
    inputPath        string // path to an input resource
    cryptType        string // type of something (private key)
    length           int    // the length of something (private key)
    privateKeyPath   string // path to the private key
    publicKeyPath    string // path to the public key
    signRequestPath  string // path to the certificate sign request
    certificateFlags *certFlagsContainer // container for certificate related flags
  }

  // a container for the refined flags
  flagSet struct {
    PrivateKey pki.PrivateKey
    Output     io.WriteCloser
    Input      io.ReadCloser

    // private key specific stuff
    PrivateKeyGenerationFlags privateKeyGenerationFlags
  }

  privateKeyGenerationFlags struct {
    Type string // type of the private key (rsa, ecdsa)
    Curve elliptic.Curve // curve for ecdsa
    Size  int            // bitsize for rsa
  }

  Flags struct {
    Name           string        // name of the sub function
    flagset        *flag.FlagSet // the flagset reference for printing the help
    flag_container *paramContainer
    Flags          *flagSet      // the end result of the flag setting

    check_list     []flagCheck   // list of all checks
  }

  flagCheck func()(error)
)

// create a new flag handler with the name of the subfunction
func NewFlags(method_name string) *Flags {
  flagset := flag.NewFlagSet(method_name, flag.ExitOnError)
  flags   := &Flags{
    Name:           method_name,
    Flags:          &flagSet{},
    flagset:        flagset,
    check_list:     make([]flagCheck, 0),
    flag_container: &paramContainer{},
  }
  flagset.Usage = flags.Usage
  return flags
}

// check all parameters for validity
func (f *Flags) Parse(options []string) error {
  f.flagset.Parse(options)
  for _, check := range f.check_list {
    // TODO handle error in a betetr way (output specific help, not command help)
    if err := check(); err != nil {
      f.Usagef("%s", err)
      return err
    }
  }
  return nil
}

// print a message with the usage part
func (f *Flags) Usagef(message string, args ...interface{}) {
  fmt.Fprintf(os.Stderr, "error: " + message + "\n", args...)
  f.Usage()
}

// print the usage of the current flag set
func (f *Flags) Usage() {
  fmt.Fprintf(os.Stderr, "usage: %s %s [options]\n", os.Args[0], f.Name)
  fmt.Fprint(os.Stderr,  "where options are:\n")
  f.flagset.PrintDefaults()
}

// add the private key option to the requested flags
func (f *Flags) AddPrivateKey() {
  f.check_list = append(f.check_list, f.parsePrivateKey)
  f.flagset.StringVar(&f.flag_container.privateKeyPath, "private-key", "", "path to the private key")
}

// check the private key flag and load the private key
func (f *Flags) parsePrivateKey() error {
  if f.flag_container.privateKeyPath == "" { return fmt.Errorf("No private key given!") }
  // check permissions of private key file
  info, err := os.Stat(f.flag_container.privateKeyPath)
  if err != nil { return fmt.Errorf("Error reading private key: %s", err) }
  if info.Mode().Perm().String()[4:] != "------" {
    return fmt.Errorf("private key file modifyable by others!")
  }

  pk, err := ReadPrivateKeyFile(f.flag_container.privateKeyPath)
  if err != nil { return fmt.Errorf("Error reading private key: %s", err) }
  f.Flags.PrivateKey = pk
  return nil
}

// add the output parameter to the checklist
func (f *Flags) AddOutput() {
  f.check_list = append(f.check_list, f.parseOutput)
  f.flagset.StringVar(&f.flag_container.outputPath, "output", "STDOUT", "path to the output or STDOUT")
}

// parse the output parameter and open the file handle
func (f *Flags) parseOutput() error {
  if f.flag_container.outputPath == "STDOUT" {
    f.Flags.Output = os.Stdout
    return nil
  }
  var err error
  f.Flags.Output, err = os.OpenFile(
    f.flag_container.outputPath,
    os.O_WRONLY | os.O_APPEND | os.O_CREATE, // do not kill users files!
    0600,
  )
  if err != nil { return err }
  return nil
}

// add the input parameter to load resources from
func (f *Flags) AddInput() {
  f.check_list = append(f.check_list, f.parseInput)
  f.flagset.StringVar(&f.flag_container.inputPath, "input", "STDIN", "path to the input or STDIN")
}

// parse the input parameter and open the file handle
func (f *Flags) parseInput() error {
  if f.flag_container.inputPath == "STDIN" {
    f.Flags.Input = os.Stdin
    return nil
  }
  var err error
  f.Flags.Input, err = os.Open(f.flag_container.inputPath)
  if err != nil { return err }
  return nil
}

// This function adds the private key generation flags.
func (f *Flags) AddPrivateKeyGenerationFlags() {
  f.check_list = append(f.check_list, f.parsePrivateKeyGenerationFlags)
  f.flagset.StringVar(&f.flag_container.cryptType, "type", "ecdsa", "the type of the private key (ecdsa, rsa)")
  f.flagset.IntVar(
    &f.flag_container.length,
    "length", 521,
    fmt.Sprintf("%d - %d for rsa; %v for ecdsa", RsaLowerLength, RsaUpperLength, EcdsaCurves),
  )
}

func (f *Flags) parsePrivateKeyGenerationFlags() error {
  pk_type := f.flag_container.cryptType
  f.Flags.PrivateKeyGenerationFlags.Type = pk_type
  switch pk_type {
  case "ecdsa":
    switch f.flag_container.length {
    case 224: f.Flags.PrivateKeyGenerationFlags.Curve = elliptic.P224()
    case 256: f.Flags.PrivateKeyGenerationFlags.Curve = elliptic.P256()
    case 384: f.Flags.PrivateKeyGenerationFlags.Curve = elliptic.P384()
    case 521: f.Flags.PrivateKeyGenerationFlags.Curve = elliptic.P521()
    default: return fmt.Errorf("Curve %d unknown!", f.flag_container.length)
    }
  case "rsa":
    size := f.flag_container.length
    if RsaLowerLength <= size && size <= RsaUpperLength {
      f.Flags.PrivateKeyGenerationFlags.Size = size
    } else {
      return fmt.Errorf("Length of %d is not allowed for rsa!", size)
    }
  default: return fmt.Errorf("Type %s is unknown!", pk_type)
  }
  return nil
}
