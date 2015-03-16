package main

// This file handles the complete parameter assignment, as some parameters are
// often used by multiple functions.

import (
  "crypto/elliptic"
  "encoding/base64"
  "encoding/pem"
  "flag"
  "fmt"
  "io"
  "io/ioutil"
  "net"
  "os"
  "reflect"
  "strings"

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
    manual struct {
      serialNumber   string // the serial number for the cert
      commonName     string // the common name used in the cert
      dnsNames       string // all alternative names in the certificate (comma separated list)
      ipAddresses    string // all IP addresses in the certificate (comma separated list)
      emailAddresses string // alternative email addresses
    }
    automatic struct {
      Country       string // the country names which should end up in the cert (comma separated list)
      Organization  string // the organization names (comma separated list)
      OrganizationalUnit string // the organizational units (comma separated list)
      Locality      string // the city or locality (comma separated list)
      Province      string // the province name (comma separated list)
      StreetAddress string // the street addresses of the organization (comma separated list)
      PostalCode    string // the postal codes of the locality
    }
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
    certificateFlags certFlagsContainer // container for certificate related flags
    signature        string // a base64 encoded signature
  }

  // a container for the refined flags
  flagSet struct {
    // loaded private key
    PrivateKey pki.PrivateKey
    // loaded public key
    PublicKey  pki.PublicKey
    // the IO handler for input
    Input      io.ReadCloser
    // the IO handler for output
    Output     io.WriteCloser
    // signature from the args
    Signature  []byte
    // private key specific stuff
    PrivateKeyGenerationFlags privateKeyGenerationFlags
    // a certificate filled with the parameters
    CertificateData *pki.CertificateData
    // the certificate sign request
    CertificateSignRequest *pki.CertificateRequest
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

// add the public key flag
func (f *Flags) AddPublicKey() {
  f.check_list = append(f.check_list, f.parsePublicKey)
  f.flagset.StringVar(&f.flag_container.publicKeyPath, "public-key", "", "path to the public key")
}

// parse public key flag
func (f *Flags) parsePublicKey() error {
  if f.flag_container.publicKeyPath == "" { return fmt.Errorf("No public key given!") }

  pu, err := ReadPublicKeyFile(f.flag_container.publicKeyPath)
  if err != nil { return fmt.Errorf("Error reading public key: %s", err) }
  f.Flags.PublicKey = pu
  return nil
}

// add flag to load certificate sign request
func (f *Flags) AddCSR() {
  f.check_list = append(f.check_list, f.parseCSR)
  f.flagset.StringVar(&f.flag_container.signRequestPath, "csr-path", "", "path to the certificate sign request")
}

// parse the certificate sign request
func (f *Flags) parseCSR() error {
  rest, err := ioutil.ReadFile(f.flag_container.signRequestPath)
  if err != nil { return fmt.Errorf("Error reading certificate sign request: %s", err) }

  var csr_asn1 []byte
  var block *pem.Block
  for len(rest) > 0 {
    block, rest = pem.Decode(rest)
    if block.Type == "CERTIFICATE REQUEST" {
      csr_asn1 = block.Bytes
      break
    }
  }
  if len(csr_asn1) == 0 {
    return fmt.Errorf(
      "No certificate sign request found in %s",
      f.flag_container.signRequestPath,
    )
  }

  csr, err := pki.LoadCertificateSignRequest(csr_asn1)
  if err != nil { return fmt.Errorf("Invalid certificate sign request: %s", err) }
  f.Flags.CertificateSignRequest = csr
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

// add the signature flag to load a signature from a signing process
func (f *Flags) AddSignature() {
  f.check_list = append(f.check_list, f.parseSignature)
  f.flagset.StringVar(&f.flag_container.signature, "signature", "", "the base64 encoded signature to use for verification")
}

// parse the signature flag
func (f *Flags) parseSignature() error {
  var err error
  f.Flags.Signature, err = base64.StdEncoding.DecodeString(f.flag_container.signature)
  if err != nil { return err }
  return nil
}

// add the certificate fields to the flags
func (f *Flags) AddCertificateFields() {
  f.check_list = append(f.check_list, f.parseCertificateFields)
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.manual.serialNumber,
    "serial", "1", "unique serial number of the CA");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.manual.commonName,
    "common-name", "", "common name of the entity to certify");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.manual.dnsNames,
    "dns-names", "", "comma separated list of alternative fqdn entries for the entity");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.manual.emailAddresses,
    "email-address", "", "comma separated list of alternative email entries for the entity");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.manual.ipAddresses,
    "ip-address", "", "comma separated list of alternative ip entries for the entity");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.automatic.Country,
    "country", "", "comma separated list of countries the entitiy resides in");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.automatic.Organization,
    "organization", "", "comma separated list of organizations the entity belongs to");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.automatic.OrganizationalUnit,
    "organization-unit", "", "comma separated list of organization units or departments the entity belongs to");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.automatic.Locality,
    "locality", "", "comma separated list of localities or cities the entity resides in");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.automatic.Province,
    "province", "", "comma separated list of provinces the entity resides in");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.automatic.StreetAddress,
    "street-address", "", "comma separated list of street addresses the entity resides in");
  f.flagset.StringVar(
    &f.flag_container.certificateFlags.automatic.PostalCode,
    "postal-code", "", "comma separated list of postal codes of the localities");
}

// parse the certificate fields into a raw certificate
func (f *Flags) parseCertificateFields() error {
  f.Flags.CertificateData = pki.NewCertificateData()
  // convert the automatic flags
  container_type := reflect.ValueOf(&f.flag_container.certificateFlags.automatic).Elem()
  cert_data_type := reflect.ValueOf(&f.Flags.CertificateData.Subject).Elem()

  for _, field := range []string{"Country", "Organization", "OrganizationalUnit",
                                 "Locality", "Province", "StreetAddress", "PostalCode"} {
    field_value := container_type.FieldByName(field).String()
    if field_value == "" { continue }
    target := cert_data_type.FieldByName(field)
    target.Set(reflect.ValueOf(strings.Split(field_value, ",")))
  }

  // convert the manual flags
  data     := f.Flags.CertificateData
  raw_data := f.flag_container.certificateFlags.manual
  data.Subject.SerialNumber = raw_data.serialNumber
  data.Subject.CommonName   = raw_data.commonName
  if raw_data.dnsNames != "" {
    data.DNSNames             = strings.Split(raw_data.dnsNames, ",")
  }
  if raw_data.emailAddresses != "" {
    data.EmailAddresses       = strings.Split(raw_data.emailAddresses, ",")
  }

  if raw_data.ipAddresses == "" { return nil }
  raw_ips := strings.Split(raw_data.ipAddresses, ",")
  data.IPAddresses = make([]net.IP, len(raw_ips))
  for i, ip := range raw_ips {
    data.IPAddresses[i] = net.ParseIP(ip)
    if data.IPAddresses[i] == nil {
      return fmt.Errorf("'%s' is not a valid IP", ip)
    }
  }

  return nil
}
