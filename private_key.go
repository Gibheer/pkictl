package main

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"os"

	"github.com/gibheer/pki"
)

const (
	RsaLowerLength = 2048
	RsaUpperLength = 16384
)

var (
	// error messages
	ErrNoPKFound     = errors.New("no private key found")
	ErrNoPUFound     = errors.New("no public key found")
	ErrUnknownFormat = errors.New("key is an unknown format")

	// the possible ecdsa curves allowed to be used
	EcdsaCurves = []int{224, 256, 384, 521}

	// Command to create a private key
	CmdCreatePrivateKey = &Command{
		Use:     "create-private",
		Short:   "create a private key",
		Long:    "Create an ecdsa or rsa key with this command",
		Example: "create-private -type=ecdsa -length=521",
		Run:     create_private_key,
	}
	// private key specific stuff
	FlagPrivateKeyGeneration privateKeyGenerationFlags
)

type (
	// The flags specific to create a private key
	privateKeyGenerationFlags struct {
		Type  string         // type of the private key (rsa, ecdsa)
		Curve elliptic.Curve // curve for ecdsa
		Size  int            // bitsize for rsa
	}
)

// create a new private key
func create_private_key(cmd *Command, args []string) {
	err := checkFlags(checkOutput, checkPrivateKeyGeneration)
	if err != nil {
		crash_with_help(cmd, ErrorFlagInput, "Flags invalid: %s", err)
	}

	var pk pki.Pemmer
	switch FlagPrivateKeyGeneration.Type {
	case "ecdsa":
		pk, err = pki.NewPrivateKeyEcdsa(FlagPrivateKeyGeneration.Curve)
	case "rsa":
		pk, err = pki.NewPrivateKeyRsa(FlagPrivateKeyGeneration.Size)
	default:
		crash_with_help(cmd, ErrorInput, "Unknown private key type '%s'", FlagPrivateKeyGeneration.Type)
	}
	if err != nil {
		crash_with_help(cmd, ErrorProgram, "Error creating private key: %s", err)
	}
	marsh_pem, err := pk.MarshalPem()
	if err != nil {
		crash_with_help(cmd, ErrorProgram, "Error when marshalling to pem: %s", err)
	}
	_, err = marsh_pem.WriteTo(FlagOutput)
	if err != nil {
		crash_with_help(cmd, ErrorProgram, "Error when writing output: %s", err)
	}
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

// Read the private key from the path and try to figure out which type of key it
// might be.
func ReadPrivateKeyFile(path string) (pki.PrivateKey, error) {
	raw_pk, err := readSectionFromFile(path, pki.PemLabelEcdsa)
	if err == nil {
		pk, err := pki.LoadPrivateKeyEcdsa(raw_pk)
		if err != nil {
			return nil, err
		}
		return pk, nil
	}
	raw_pk, err = readSectionFromFile(path, pki.PemLabelRsa)
	if err == nil {
		pk, err := pki.LoadPrivateKeyRsa(raw_pk)
		if err != nil {
			return nil, err
		}
		return pk, nil
	}
	return nil, ErrNoPKFound
}

// read the public key and try to figure out what kind of key it might be
func ReadPublicKeyFile(path string) (pki.PublicKey, error) {
	raw_pu, err := readSectionFromFile(path, pki.PemLabelPublic)
	if err != nil {
		return nil, ErrNoPUFound
	}

	var public pki.PublicKey
	public, err = pki.LoadPublicKeyEcdsa(raw_pu)
	if err == nil {
		return public, nil
	}
	public, err = pki.LoadPublicKeyRsa(raw_pu)
	if err == nil {
		return public, nil
	}
	return nil, ErrUnknownFormat
}
