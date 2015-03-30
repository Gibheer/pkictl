package main

// This file handles the complete parameter assignment, as some parameters are
// often used by multiple functions.

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/gibheer/pki"
)

const (
	RsaLowerLength = 2048
	RsaUpperLength = 16384
)

var (
	EcdsaCurves    = []int{224, 256, 384, 521}
	ValidKeyUsages = map[string]x509.KeyUsage{
		"digitalsignature":  x509.KeyUsageDigitalSignature,
		"contentcommitment": x509.KeyUsageContentCommitment,
		"keyencipherment":   x509.KeyUsageKeyEncipherment,
		"dataencipherment":  x509.KeyUsageDataEncipherment,
		"keyagreement":      x509.KeyUsageKeyAgreement,
		"certsign":          x509.KeyUsageCertSign,
		"crlsign":           x509.KeyUsageCRLSign,
		"encipheronly":      x509.KeyUsageEncipherOnly,
		"decipheronly":      x509.KeyUsageDecipherOnly,
	}
)

type (
	// holds all certificate related flags, which need parsing afterwards
	certiticateRequestRawFlags struct {
		manual struct {
			serialNumber   string // the serial number for the cert
			commonName     string // the common name used in the cert
			dnsNames       string // all alternative names in the certificate (comma separated list)
			ipAddresses    string // all IP addresses in the certificate (comma separated list)
			emailAddresses string // alternative email addresses
		}
		automatic struct {
			Country            string // the country names which should end up in the cert (comma separated list)
			Organization       string // the organization names (comma separated list)
			OrganizationalUnit string // the organizational units (comma separated list)
			Locality           string // the city or locality (comma separated list)
			Province           string // the province name (comma separated list)
			StreetAddress      string // the street addresses of the organization (comma separated list)
			PostalCode         string // the postal codes of the locality
		}
	}

	// a container go gather all incoming flags for further processing
	paramContainer struct {
		outputPath       string                     // path to output whatever is generated
		inputPath        string                     // path to an input resource
		cryptType        string                     // type of something (private key)
		length           int                        // the length of something (private key)
		privateKeyPath   string                     // path to the private key
		publicKeyPath    string                     // path to the public key
		signRequestPath  string                     // path to the certificate sign request
		certificateFlags certiticateRequestRawFlags // container for certificate related flags
		signature        string                     // a base64 encoded signature
		certGeneration   certGenerationRaw          // all certificate generation flags
		certificatePath  string                     // path to a certificate
	}

	privateKeyGenerationFlags struct {
		Type  string         // type of the private key (rsa, ecdsa)
		Curve elliptic.Curve // curve for ecdsa
		Size  int            // bitsize for rsa
	}

	certGenerationRaw struct {
		serial    int64
		notBefore string
		notAfter  string
		isCA      bool
		length    int
		caPath    string // path to the ca file if isCA is false
		keyUsage  string // comma separated list of key usages
	}

	flagCheck func() error
)

var (
	CmdRoot = &Command{
		Short: "A tool to manage keys and certificates.",
		Long: `This tool provides a way to manage private and public keys, create
certificate requests and certificates and sign/verify messages.`,
	}

	CmdCreatePrivateKey = &Command{
		Use:     "create-private",
		Short:   "create a private key",
		Long:    "Create an ecdsa or rsa key with this command",
		Example: "create-private -type=ecdsa -length=521",
		Run:     create_private_key,
	}

	CmdCreatePublicKey = &Command{
		Use:     "create-public",
		Short:   "create a public key from a private key",
		Long:    "Create a public key derived from a private key.",
		Example: "create-public -private-key=foo.ecdsa",
		Run:     create_public_key,
	}

	CmdSignInput = &Command{
		Use:     "sign-input",
		Short:   "sign a text using a private key",
		Long:    "Create a signature using a private key",
		Example: "sign-input -private-key=foo.ecdsa -input=textfile",
		Run:     sign_input,
	}

	CmdVerifyInput = &Command{
		Use:     "verify-input",
		Short:   "verify a text using a signature",
		Long:    "Verify a text using a signature and a public key.",
		Example: "verify-input -public-key=foo.ecdsa.pub -input=textfile -signature=abc456",
		Run:     verify_input,
	}

	CmdCreateSignRequest = &Command{
		Use:     "create-sign-request",
		Short:   "create a certificate sign request",
		Long:    "Create a certificate sign request.",
		Example: "create-sign-request -private-key=foo.ecdsa -common-name=foo -serial=1",
		Run:     create_sign_request,
	}

	CmdCreateCert = &Command{
		Use:     "create-cert",
		Short:   "create a certificate from a sign request",
		Long:    "Create a certificate based on a certificate sign request.",
		Example: "create-cert -private-key=foo.ecdsa -csr-path=foo.csr",
		Run:     create_cert,
	}

	// variable to hold the raw arguments before checking
	flagContainer *paramContainer

	// loaded private key
	FlagPrivateKey pki.PrivateKey
	// loaded public key
	FlagPublicKey pki.PublicKey
	// the IO handler for input
	FlagInput io.ReadCloser
	// the IO handler for output
	FlagOutput io.WriteCloser
	// signature from the args
	FlagSignature []byte
	// private key specific stuff
	FlagPrivateKeyGeneration privateKeyGenerationFlags
	// a certificate filled with the parameters
	FlagCertificateRequestData *pki.CertificateData
	// the certificate sign request
	FlagCertificateSignRequest *pki.CertificateRequest
	// certificate specific creation stuff
	FlagCertificateGeneration pki.CertificateOptions
)

func InitFlags() {
	flagContainer = &paramContainer{}
	CmdRoot.AddCommand(
		CmdCreatePrivateKey,
		CmdCreatePublicKey,
		CmdSignInput,
		CmdVerifyInput,
		CmdCreateSignRequest,
		CmdCreateCert,
	)

	// private-key
	InitFlagOutput(CmdCreatePrivateKey)
	InitFlagPrivateKeyGeneration(CmdCreatePrivateKey)
	// public-key
	InitFlagOutput(CmdCreatePublicKey)
	InitFlagPrivateKey(CmdCreatePublicKey)
	// sign-input
	InitFlagInput(CmdSignInput)
	InitFlagPrivateKey(CmdSignInput)
	InitFlagOutput(CmdSignInput)
	// verify-input
	InitFlagInput(CmdVerifyInput)
	InitFlagPrivateKey(CmdVerifyInput)
	InitFlagOutput(CmdVerifyInput)
	InitFlagSignature(CmdVerifyInput)
	// create-sign-request
	InitFlagPrivateKey(CmdCreateSignRequest)
	InitFlagOutput(CmdCreateSignRequest)
	InitFlagCertificateFields(CmdCreateSignRequest)
	// create-certificate
	InitFlagPrivateKey(CmdCreateCert)
	InitFlagOutput(CmdCreateCert)
	InitFlagCert(CmdCreateCert)
	InitFlagCSR(CmdCreateCert)
}

func checkFlags(checks ...flagCheck) error {
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

//// print a message with the usage part
//func (f *Flags) Usagef(message string, args ...interface{}) {
//  fmt.Fprintf(os.Stderr, "error: " + message + "\n", args...)
//  f.flagset.Flags().Usage()
//}

// add the private key option to the requested flags
func InitFlagPrivateKey(cmd *Command) {
	cmd.Flags().StringVar(&flagContainer.privateKeyPath, "private-key", "", "path to the private key (required)")
}

// check the private key flag and load the private key
func checkPrivateKey() error {
	if flagContainer.privateKeyPath == "" {
		return fmt.Errorf("No private key given!")
	}
	// check permissions of private key file
	info, err := os.Stat(flagContainer.privateKeyPath)
	if err != nil {
		return fmt.Errorf("Error reading private key: %s", err)
	}
	if info.Mode().Perm().String()[4:] != "------" {
		return fmt.Errorf("private key file modifyable by others!")
	}

	pk, err := ReadPrivateKeyFile(flagContainer.privateKeyPath)
	if err != nil {
		return fmt.Errorf("Error reading private key: %s", err)
	}
	FlagPrivateKey = pk
	return nil
}

// add the public key flag
func InitFlagPublicKey(cmd *Command) {
	cmd.Flags().StringVar(&flagContainer.publicKeyPath, "public-key", "", "path to the public key (required)")
}

// parse public key flag
func checkPublicKey() error {
	if flagContainer.publicKeyPath == "" {
		return fmt.Errorf("No public key given!")
	}

	pu, err := ReadPublicKeyFile(flagContainer.publicKeyPath)
	if err != nil {
		return fmt.Errorf("Error reading public key: %s", err)
	}
	FlagPublicKey = pu
	return nil
}

// add flag to load certificate flags
func InitFlagCert(cmd *Command) {
	cmd.Flags().Int64Var(&flagContainer.certGeneration.serial, "serial", 0, "serial number of all certificates")
	cmd.Flags().BoolVar(&flagContainer.certGeneration.isCA, "ca", false, "check if the resulting certificate is a ca")
	cmd.Flags().IntVar(
		&flagContainer.certGeneration.
			length,
		"length",
		0,
		"the number of certificates allowed in the chain between this cert and the end certificate",
	)
	cmd.Flags().StringVar(
		&flagContainer.certGeneration.notBefore,
		"not-before",
		time.Now().Format(time.RFC3339),
		"time before the certificate is not valid in RFC3339 format (default now)",
	)
	cmd.Flags().StringVar(
		&flagContainer.certGeneration.notAfter,
		"not-after",
		time.Now().Add(time.Duration(180*24*time.Hour)).Format(time.RFC3339),
		"time after which the certificate is not valid in RFC3339 format (default now + 180 days)",
	)
	cmd.Flags().StringVar(
		&flagContainer.certGeneration.keyUsage,
		"key-usage",
		"",
		"comma separated list of key usages",
	)
}

// parse the certificate data
func checkCertFlags() error {
	FlagCertificateGeneration.IsCA = flagContainer.certGeneration.isCA
	FlagCertificateGeneration.CALength = flagContainer.certGeneration.length
	FlagCertificateGeneration.SerialNumber = big.NewInt(flagContainer.certGeneration.serial)

	var err error
	if notbefore := flagContainer.certGeneration.notBefore; notbefore != "" {
		FlagCertificateGeneration.NotBefore, err = parseTimeRFC3339(notbefore)
		if err != nil {
			return err
		}
	}
	if notafter := flagContainer.certGeneration.notAfter; notafter != "" {
		FlagCertificateGeneration.NotAfter, err = parseTimeRFC3339(notafter)
		if err != nil {
			return err
		}
	}
	// parse the key usage string
	if keyUstr := flagContainer.certGeneration.keyUsage; keyUstr != "" {
		keyUarr := strings.Split(keyUstr, ",")
		var keyUresult x509.KeyUsage
		for _, usage := range keyUarr {
			if value, ok := ValidKeyUsages[strings.ToLower(usage)]; ok {
				keyUresult = keyUresult | value
			} else {
				return fmt.Errorf("unsupported key usage '%s'", usage)
			}
		}
		FlagCertificateGeneration.KeyUsage = keyUresult
	}
	return nil
}

func parseTimeRFC3339(tr string) (time.Time, error) {
	return time.Parse(time.RFC3339, tr)
}

// add flag to load certificate sign request
func InitFlagCSR(cmd *Command) {
	cmd.Flags().StringVar(&flagContainer.signRequestPath, "csr-path", "", "path to the certificate sign request")
}

// parse the certificate sign request
func checkCSR() error {
	rest, err := ioutil.ReadFile(flagContainer.signRequestPath)
	if err != nil {
		return fmt.Errorf("Error reading certificate sign request: %s", err)
	}

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
			flagContainer.signRequestPath,
		)
	}

	csr, err := pki.LoadCertificateSignRequest(csr_asn1)
	if err != nil {
		return fmt.Errorf("Invalid certificate sign request: %s", err)
	}
	FlagCertificateSignRequest = csr
	return nil
}

func InitFlagOutput(cmd *Command) {
	cmd.Flags().StringVar(&flagContainer.outputPath, "output", "STDOUT", "path to the output or STDOUT")
}

// parse the output parameter and open the file handle
func checkOutput() error {
	if flagContainer.outputPath == "STDOUT" {
		FlagOutput = os.Stdout
		return nil
	}
	var err error
	FlagOutput, err = os.OpenFile(
		flagContainer.outputPath,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE, // do not kill users files!
		0600,
	)
	if err != nil {
		return err
	}
	return nil
}

// add the input parameter to load resources from
func InitFlagInput(cmd *Command) {
	cmd.Flags().StringVar(&flagContainer.inputPath, "input", "STDIN", "path to the input or STDIN")
}

// parse the input parameter and open the file handle
func checkInput() error {
	if flagContainer.inputPath == "STDIN" {
		FlagInput = os.Stdin
		return nil
	}
	var err error
	FlagInput, err = os.Open(flagContainer.inputPath)
	if err != nil {
		return err
	}
	return nil
}

// This function adds the private key generation flags.
func InitFlagPrivateKeyGeneration(cmd *Command) {
	cmd.Flags().StringVar(&flagContainer.cryptType, "type", "ecdsa", "the type of the private key (ecdsa, rsa)")
	cmd.Flags().IntVar(
		&flagContainer.length,
		"length", 521,
		fmt.Sprintf("%d - %d for rsa; one of %v for ecdsa", RsaLowerLength, RsaUpperLength, EcdsaCurves),
	)
}

// check the private key generation variables and move them to the work space
func checkPrivateKeyGeneration() error {
	pk_type := flagContainer.cryptType
	FlagPrivateKeyGeneration.Type = pk_type
	switch pk_type {
	case "ecdsa":
		switch flagContainer.length {
		case 224:
			FlagPrivateKeyGeneration.Curve = elliptic.P224()
		case 256:
			FlagPrivateKeyGeneration.Curve = elliptic.P256()
		case 384:
			FlagPrivateKeyGeneration.Curve = elliptic.P384()
		case 521:
			FlagPrivateKeyGeneration.Curve = elliptic.P521()
		default:
			return fmt.Errorf("Curve %d unknown!", flagContainer.length)
		}
	case "rsa":
		size := flagContainer.length
		if RsaLowerLength <= size && size <= RsaUpperLength {
			FlagPrivateKeyGeneration.Size = size
		} else {
			return fmt.Errorf("Length of %d is not allowed for rsa!", size)
		}
	default:
		return fmt.Errorf("Type %s is unknown!", pk_type)
	}
	return nil
}

// add the signature flag to load a signature from a signing process
func InitFlagSignature(cmd *Command) {
	cmd.Flags().StringVar(&flagContainer.signature, "signature", "", "the base64 encoded signature to use for verification")
}

// parse the signature flag
func checkSignature() error {
	var err error
	FlagSignature, err = base64.StdEncoding.DecodeString(flagContainer.signature)
	if err != nil {
		return err
	}
	return nil
}

// add the certificate fields to the flags
func InitFlagCertificateFields(cmd *Command) {
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.manual.serialNumber,
		"serial", "1", "unique serial number of the CA")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.manual.commonName,
		"common-name", "", "common name of the entity to certify")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.manual.dnsNames,
		"dns-names", "", "comma separated list of alternative fqdn entries for the entity")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.manual.emailAddresses,
		"email-address", "", "comma separated list of alternative email entries for the entity")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.manual.ipAddresses,
		"ip-address", "", "comma separated list of alternative ip entries for the entity")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.automatic.Country,
		"country", "", "comma separated list of countries the entitiy resides in")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.automatic.Organization,
		"organization", "", "comma separated list of organizations the entity belongs to")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.automatic.OrganizationalUnit,
		"organization-unit", "", "comma separated list of organization units or departments the entity belongs to")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.automatic.Locality,
		"locality", "", "comma separated list of localities or cities the entity resides in")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.automatic.Province,
		"province", "", "comma separated list of provinces the entity resides in")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.automatic.StreetAddress,
		"street-address", "", "comma separated list of street addresses the entity resides in")
	cmd.Flags().StringVar(
		&flagContainer.certificateFlags.automatic.PostalCode,
		"postal-code", "", "comma separated list of postal codes of the localities")
}

// parse the certificate fields into a raw certificate
func checkCertificateFields() error {
	FlagCertificateRequestData = pki.NewCertificateData()
	// convert the automatic flags
	container_type := reflect.ValueOf(&flagContainer.certificateFlags.automatic).Elem()
	cert_data_type := reflect.ValueOf(&FlagCertificateRequestData.Subject).Elem()

	for _, field := range []string{"Country", "Organization", "OrganizationalUnit",
		"Locality", "Province", "StreetAddress", "PostalCode"} {
		field_value := container_type.FieldByName(field).String()
		if field_value == "" {
			continue
		}
		target := cert_data_type.FieldByName(field)
		target.Set(reflect.ValueOf(strings.Split(field_value, ",")))
	}

	// convert the manual flags
	data := FlagCertificateRequestData
	raw_data := flagContainer.certificateFlags.manual
	data.Subject.SerialNumber = raw_data.serialNumber
	data.Subject.CommonName = raw_data.commonName
	if raw_data.dnsNames != "" {
		data.DNSNames = strings.Split(raw_data.dnsNames, ",")
	}
	if raw_data.emailAddresses != "" {
		data.EmailAddresses = strings.Split(raw_data.emailAddresses, ",")
	}

	if raw_data.ipAddresses == "" {
		return nil
	}
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
