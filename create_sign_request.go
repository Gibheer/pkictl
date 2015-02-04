package main

// create a sign request needed for the final certificate

import (
  "crypto"
  "crypto/rand"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
  "fmt"
  "flag"
  "io"
  "net"
  "os"
  "reflect"
  "regexp"
)

type (
  SignFlags struct {
    PrivateKeyPath string // path to the private key
    Output         string // path where to store the CSR
    BaseAttributes pkix.Name
    DNSNames       []string // alternative names to the BaseAttributes.CommonName
    IPAddresses    []net.IP // alternative IP addresses

    private_key crypto.Signer
    output_stream io.Writer // the output stream for the CSR
  }
)

var (
  COMMA_SPLIT = regexp.MustCompile(`,[[:space:]]?`)
)

// create a sign request with a private key
func create_sign_request() {
  flags := parse_sign_flags()
  flags.private_key = load_private_key(flags.PrivateKeyPath)

  stream, err := open_output_stream(flags.Output)
  if err != nil {
    crash_with_help(2, fmt.Sprintf("Error when creating file %s: %s", flags.Output, err))
  }
  defer stream.Close()
  flags.output_stream = stream

  if err = create_csr(flags); err != nil {
    fmt.Fprintln(os.Stderr, "Error when generating CSR: ", err)
    os.Exit(3)
  }
}

// parse the flags to create a certificate sign request
func parse_sign_flags() SignFlags {
  dns_names := "" // string to hold the alternative names
  ips       := "" // string to hold the alternative ips
  var container struct {
      Country, Organization, OrganizationalUnit, Locality, Province,
      StreetAddress, PostalCode string
  }

  flags := SignFlags{}
  fs := flag.NewFlagSet("create-cert-sign", flag.ExitOnError)
  fs.StringVar(&flags.PrivateKeyPath, "private-key", "", "path to the private key file")
  fs.StringVar(&flags.Output, "output", "STDOUT", "path where the generated csr should be stored")

  flags.BaseAttributes = pkix.Name{}
  fs.StringVar(&flags.BaseAttributes.CommonName, "common-name", "", "the name of the resource")
  fs.StringVar(&flags.BaseAttributes.SerialNumber, "serial", "1", "serial number for the request")
  fs.StringVar(&dns_names, "names", "", "alternative names (comma separated)")
  fs.StringVar(&ips, "ips", "", "alternative IPs (comma separated)")
  fs.StringVar(&container.Country, "country", "", "country of the organization")
  fs.StringVar(&container.Organization, "organization", "", "the name of the organization")
  fs.StringVar(&container.OrganizationalUnit, "org-unit", "", "the organizational unit")
  fs.StringVar(&container.Locality, "city", "", "the city or locality")
  fs.StringVar(&container.Province, "province", "", "the province")
  fs.StringVar(&container.StreetAddress, "street", "", "the street address for the cert")
  fs.StringVar(&container.PostalCode, "postal-code", "", "the postal code of the city")
  fs.Parse(os.Args[2:])

  // convert array flags to config structs
  if dns_names != "" {
    flags.DNSNames =  COMMA_SPLIT.Split(dns_names, -1)
  }
  if ips != "" {
    tmp_ips        := COMMA_SPLIT.Split(ips, -1)
    for _, sip := range tmp_ips {
      flags.IPAddresses = append(flags.IPAddresses, net.ParseIP(sip))
    }
  }

  container_type := reflect.ValueOf(container)
  config_type    := reflect.ValueOf(&flags.BaseAttributes).Elem()
  for i := 0; i < container_type.NumField(); i++ {
    field     := container_type.Field(i)
    new_field := config_type.FieldByName(container_type.Type().Field(i).Name)
    new_field.Set(reflect.ValueOf(COMMA_SPLIT.Split(field.String(), -1)))
  }

  return flags
}

// generate the csr and print into flags.output_stream
func create_csr(flags SignFlags) (error) {
  csr_template := &x509.CertificateRequest{
    Subject:     flags.BaseAttributes,
    DNSNames:    flags.DNSNames,
    IPAddresses: flags.IPAddresses,
  }
  csr_raw, err := x509.CreateCertificateRequest(rand.Reader, csr_template, flags.private_key)
  if err != nil { return err }

  block := &pem.Block{Type: TypeLabelCSR, Bytes: csr_raw}
  pem.Encode(flags.output_stream, block)
  return nil
}
