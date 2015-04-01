package main

// This file contains all code to create certificates.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"time"

	"github.com/gibheer/pki"
)

var (
	// the possible valid key usages to check against the commandline
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
	// the valid extended key usages, to check against the commandline
	ValidExtKeyUsages = map[string]x509.ExtKeyUsage{
		"any":                        x509.ExtKeyUsageAny,
		"serverauth":                 x509.ExtKeyUsageServerAuth,
		"clientauth":                 x509.ExtKeyUsageClientAuth,
		"codesigning":                x509.ExtKeyUsageCodeSigning,
		"emailprotection":            x509.ExtKeyUsageEmailProtection,
		"ipsecendsystem":             x509.ExtKeyUsageIPSECEndSystem,
		"ipsectunnel":                x509.ExtKeyUsageIPSECTunnel,
		"ipsecuser":                  x509.ExtKeyUsageIPSECUser,
		"timestamping":               x509.ExtKeyUsageTimeStamping,
		"ocspsigning":                x509.ExtKeyUsageOCSPSigning,
		"microsoftservergatedcrypto": x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		"netscapeservergatedcrypto":  x509.ExtKeyUsageNetscapeServerGatedCrypto,
	}

	CmdCreateCert = &Command{
		Use:     "create-cert",
		Short:   "create a certificate from a sign request",
		Long:    "Create a certificate based on a certificate sign request.",
		Example: "create-cert -private-key=foo.ecdsa -csr-path=foo.csr",
		Run:     create_cert,
	}
	// certificate specific creation stuff
	FlagCertificateGeneration pki.CertificateOptions
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

	// the raw flags collected through flags
	certGenerationRaw struct {
		serial      int64
		notBefore   string
		notAfter    string
		isCA        bool
		length      int
		caPath      string // path to the ca file if isCA is false
		keyUsage    string // comma separated list of key usages
		extKeyUsage string // comma separated list of extended key usages
		crlUrl      string // comma separated list of crl urls
	}
)

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
		"key-usage", "",
		"comma separated list of key usages",
	)
	cmd.Flags().StringVar(
		&flagContainer.certGeneration.extKeyUsage,
		"ext-key-usage", "",
		"comma separated list of extended key usage flags",
	)
	cmd.Flags().StringVar(
		&flagContainer.certGeneration.crlUrl,
		"crl-url", "",
		"comma separated list where crl lists can be found",
	)
}

// create a certificate
func create_cert(cmd *Command, args []string) {
	err := checkFlags(checkPrivateKey, checkOutput, checkCSR, checkCertFlags)
	if err != nil {
		crash_with_help(cmd, ErrorFlagInput, "Flags invalid: %s", err)
	}

	// TODO implement flags for all certificate options
	cert, err := FlagCertificateSignRequest.ToCertificate(
		FlagPrivateKey,
		FlagCertificateGeneration,
		nil,
	)
	if err != nil {
		crash_with_help(cmd, ErrorProgram, "Error generating certificate: %s", err)
	}
	pem_block, err := cert.MarshalPem()
	if err != nil {
		crash_with_help(cmd, ErrorProgram, "Error when marshalling to pem: %s", err)
	}
	_, err = pem_block.WriteTo(FlagOutput)
	if err != nil {
		crash_with_help(cmd, ErrorProgram, "Could not write to output: %s", err)
	}
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

	if err := convertCertKeyUsage(); err != nil {
		return err
	}
	if err := convertCertExtKeyUsage(); err != nil {
		return err
	}
	if err := convertCertCrlUrl(); err != nil {
		return err
	}
	return nil
}

// parse the key usage string
func convertCertKeyUsage() error {
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

// parse the extended key usage flags
func convertCertExtKeyUsage() error {
	if eKeyUstr := flagContainer.certGeneration.extKeyUsage; eKeyUstr != "" {
		eKeyUarr := strings.Split(eKeyUstr, ",")
		eKeyUResult := make([]x509.ExtKeyUsage, 0)
		for _, usage := range eKeyUarr {
			if value, ok := ValidExtKeyUsages[strings.ToLower(usage)]; ok {
				eKeyUResult = append(eKeyUResult, value)
			} else {
				return fmt.Errorf("unsupported extended key usage '%s'", usage)
			}
		}
		FlagCertificateGeneration.KeyExtendedUsage = eKeyUResult
	}
	return nil
}

// parse the crl urls
func convertCertCrlUrl() error {
	if str := flagContainer.certGeneration.crlUrl; str != "" {
		FlagCertificateGeneration.CRLUrls = strings.Split(str, ",")
	}
	return nil
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

// parse the string as a RFC3339 time
func parseTimeRFC3339(tr string) (time.Time, error) {
	return time.Parse(time.RFC3339, tr)
}
