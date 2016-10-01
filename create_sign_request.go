package main

import (
	"crypto/x509/pkix"
	"flag"
	"fmt"

	"github.com/gibheer/pki"
)

func CreateSignRequest(args []string) error {
	var (
		flagPrivate string
		flagOutput  string
		// primary certificate fields
		flagSerial      string
		flagCommonName  string
		flagDnsNames    stringList
		flagEmails      stringList
		flagIpAddresses ipList
		// standard simple entry flags
		flagCountry         stringList
		flagOrganization    stringList
		flagOrganizaionUnit stringList
		flagLocality        stringList
		flagProvince        stringList
		flagStreetAddress   stringList
		flagPostalCode      stringList
	)
	fs := flag.NewFlagSet("pkictl create-sign-request", flag.ExitOnError)
	fs.StringVar(&flagPrivate, "private-key", "", "the private key to generate the request")
	fs.StringVar(&flagOutput, "output", "stdout", "path to the output file (default stdout)")
	// primary certificate info
	fs.StringVar(&flagSerial, "serial", "", "the serial for the sign request")
	fs.StringVar(&flagCommonName, "common-name", "", "the primary name of the certificate (or common name)")
	fs.Var(&flagDnsNames, "names", "additional names accepted by the certificate")
	fs.Var(&flagEmails, "mails", "mail addresses to add as contact addresses")
	fs.Var(&flagIpAddresses, "ips", "IPs to accept by the certificate")
	// standard simple entry flags
	fs.Var(&flagCountry, "country", "country of residence of the requester")
	fs.Var(&flagOrganization, "organization", "organization of the requester")
	fs.Var(&flagOrganizaionUnit, "organization-unit", "the organization unit requesting the certificate")
	fs.Var(&flagLocality, "locality", "locality of the requester")
	fs.Var(&flagProvince, "province", "province of residence")
	fs.Var(&flagStreetAddress, "street-address", "the street address of the requester")
	fs.Var(&flagPostalCode, "postal-code", "the postal code of the requester")
	fs.Parse(args)

	if flagPrivate == "" || flagSerial == "" || flagCommonName == "" {
		// TODO make the same for other parts?
		// TODO find better way to handle the situation
		fmt.Println("Error: missing private key, serial or common name")
		fmt.Println("Usage of pkictl create-sign-request:")
		fs.PrintDefaults()
		return fmt.Errorf("missing private key, serial or common name")
	}

	data := pki.CertificateData{
		Subject: pkix.Name{
			SerialNumber:       flagSerial,
			CommonName:         flagCommonName,
			Country:            flagCountry,
			Organization:       flagOrganization,
			OrganizationalUnit: flagOrganizaionUnit,
			Locality:           flagLocality,
			Province:           flagProvince,
			StreetAddress:      flagStreetAddress,
			PostalCode:         flagPostalCode,
		},
		DNSNames:       flagDnsNames,
		IPAddresses:    flagIpAddresses,
		EmailAddresses: flagEmails,
	}
	pk, err := loadPrivateKey(flagPrivate)
	if err != nil {
		return err
	}
	out, err := openOutput(flagOutput)
	if err != nil {
		return err
	}
	defer out.Close()
	var csr pki.Pemmer
	csr, err = data.ToCertificateRequest(pk)
	if err != nil {
		return err
	}
	return writePem(csr, out)
}
