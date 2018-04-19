package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"math/big"
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
)

func CreateCert(args []string) error {
	var (
		flagUsageTemplate string
		flagKeyUsage      string
		flagKeyExtUsage   stringList
		flagNotBefore     string
		flagNotAfter      string
		flagSerial        int64
		flagLength        int
		flagIsCA          bool
		flagCA            string
		flagPrivate       string
		flagCSR           string
		flagOutput        string
	)
	fs := flag.NewFlagSet("pkictl create-cert", flag.ExitOnError)
	fs.StringVar(&flagPrivate, "private-key", "", "the private key to generate the request")
	fs.StringVar(&flagCSR, "sign-request", "", "the certificate sign request")
	fs.StringVar(&flagOutput, "output", "stdout", "path to the output file (default stdout)")
	fs.BoolVar(&flagIsCA, "is-ca", false, "is the result a CA - when true ca is ignored")
	fs.StringVar(&flagUsageTemplate, "usage", "", "templates for usage (all, server, client)")
	fs.StringVar(&flagKeyUsage, "key-usage", "", "comma separated list of key usages")
	fs.Var(&flagKeyExtUsage, "key-ext-usage", "comma separated list of further usages")
	fs.Int64Var(&flagSerial, "serial", 0, "the serial for the issued certificate")
	fs.IntVar(&flagLength, "length", 0, "the number of sub CAs allowed (-1 equals no limit)")
	fs.StringVar(&flagCA, "ca", "", "path to the CA certificate")
	fs.StringVar(
		&flagNotBefore,
		"not-before",
		time.Now().Format(time.RFC3339),
		"time before the certificate is not valid in RFC3339 format (default now)",
	)
	fs.StringVar(
		&flagNotAfter,
		"not-after",
		time.Now().Format(time.RFC3339),
		"time after the certificate is not valid in RFC3339 format (default now)",
	)
	fs.Parse(args)

	if flagPrivate == "" {
		return fmt.Errorf("missing private key")
	}
	if flagCSR == "" {
		return fmt.Errorf("missing certificate sign request")
	}

	pk, err := loadPrivateKey(flagPrivate)
	if err != nil {
		return err
	}
	csr, err := parseCSR(flagCSR)
	if err != nil {
		return err
	}
	var ca *pki.Certificate
	if !flagIsCA {
		ca, err = parseCA(flagCA)
		if err != nil {
			return err
		}
	}

	notBefore, err := time.Parse(time.RFC3339, flagNotBefore)
	if err != nil {
		return err
	}
	notAfter, err := time.Parse(time.RFC3339, flagNotAfter)
	if err != nil {
		return err
	}
	if notBefore.After(notAfter) {
		return fmt.Errorf("before and after range is wrong")
	}
	cert_opts := pki.CertificateOptions{
		SerialNumber: big.NewInt(flagSerial),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         flagIsCA,
		CALength:     flagLength,
	}
	if flagKeyUsage != "" {
		keyUsage, found := ValidKeyUsages[flagKeyUsage]
		if !found {
			return fmt.Errorf("unknown key usage")
		}
		cert_opts.KeyUsage = keyUsage
	}

	for pos, name := range flagKeyExtUsage {
		if val, found := ValidExtKeyUsages[name]; !found {
			return fmt.Errorf("%d ext key usage '%s' unknown", pos, name)
		} else {
			cert_opts.KeyExtendedUsage = append(cert_opts.KeyExtendedUsage, val)
		}
	}

	cert, err := csr.ToCertificate(pk, cert_opts, ca)
	if err != nil {
		return err
	}

	out, err := openOutput(flagOutput)
	if err != nil {
		return err
	}
	// FIXME check all other out.Close for stdout exception
	if flagOutput != "stdout" {
		defer out.Close()
	}

	return writePem(cert, out)
}

func parseCSR(path string) (*pki.CertificateRequest, error) {
	pems_raw, err := openInput(path)
	if err != nil {
		return nil, fmt.Errorf("could not open file '%s': %s", path, err)
	}
	defer pems_raw.Close()
	pems, err := parseFile(pems_raw)
	if err != nil {
		return nil, fmt.Errorf("could not parse file '%s': %s", path, err)
	}
	csr_raw, err := getSectionFromPem(pems, pki.PemLabelCertificateRequest)
	if err != nil {
		return nil, fmt.Errorf("could not find sign request in '%s': %s", path, err)
	}
	csr, err := pki.LoadCertificateSignRequest(csr_raw)
	if err != nil {
		return nil, fmt.Errorf("could not load sign request from '%s': %s", path, err)
	}
	return csr, nil
}

func parseCA(path string) (*pki.Certificate, error) {
	pems_raw, err := openInput(path)
	if err != nil {
		return nil, fmt.Errorf("could not open file '%s': %s", path, err)
	}
	defer pems_raw.Close()
	pems, err := parseFile(pems_raw)
	if err != nil {
		return nil, fmt.Errorf("could not parse file '%s': %s", path, err)
	}
	ca_raw, err := getSectionFromPem(pems, pki.PemLabelCertificate)
	if err != nil {
		return nil, fmt.Errorf("could not find CA in '%s': %s", path, err)
	}
	ca, err := pki.LoadCertificate(ca_raw)
	if err != nil {
		return nil, fmt.Errorf("could not load certificate from '%s': %s", path, err)
	}
	return ca, nil
}
