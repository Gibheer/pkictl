package main

// This file handles the complete parameter assignment, as some parameters are
// often used by multiple functions.

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/gibheer/pki"
)

type (
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

	flagCheck func() error
)

var (
	CmdRoot = &Command{
		Short: "A tool to manage keys and certificates.",
		Long: `This tool provides a way to manage private and public keys, create
certificate requests and certificates and sign/verify messages.`,
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
	// a certificate filled with the parameters
	FlagCertificateRequestData *pki.CertificateData
	// the certificate sign request
	FlagCertificateSignRequest *pki.CertificateRequest
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

// initialize the output flag
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
