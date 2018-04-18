package main

import (
	"crypto/elliptic"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gibheer/pki"
)

const (
	// Lower boundary limit for RSA private keys
	RsaLowerLength = 1024
	// Upper boundary limit for RSA private keys
	RsaUpperLength = 65536
)

var (
	// the possible ecdsa curves allowed to be used
	ecdsaCurves = map[uint]elliptic.Curve{
		224: elliptic.P224(),
		256: elliptic.P256(),
		384: elliptic.P384(),
		521: elliptic.P521(),
	}
)

func CreatePrivateKey(args []string) error {
	fs := flag.NewFlagSet("pkiadm create-private-key", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "The length depends on the key type. Possible values are:\n")
		fmt.Fprintf(os.Stderr, "  * ed25519 - 256\n")
		fmt.Fprintf(os.Stderr, "  * ecdsa   - 224, 256, 384, 521\n")
		fmt.Fprintf(os.Stderr, "  * rsa     - from %d up to %d\n", RsaLowerLength, RsaUpperLength)
		fmt.Fprintf(os.Stderr, "Usage of %s %s:\n", COMMAND, "create-private")
		fs.PrintDefaults()
	}
	flagType := fs.String("type", "ed25519", "the type of the private key (ed25519, ecdsa, rsa)")
	flagLength := fs.Uint("length", 256, "the bit length for the private key")
	flagOutput := fs.String("output", "stdout", "write private key to file")
	fs.Parse(args)

	var err error
	var out io.WriteCloser
	if *flagOutput == "stdout" {
		out = os.Stdout
	} else {
		out, err = os.OpenFile(*flagOutput, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0600)
		if err != nil {
			return err
		}
	}
	defer out.Close()

	var pk pki.Pemmer
	switch *flagType {
	case "ed25519":
		if *flagLength != 256 {
			return fmt.Errorf("ed25519 only supports bit length of 256")
		}
		pk, err = pki.NewPrivateKeyEd25519()
	case "ecdsa":
		if curve, found := ecdsaCurves[*flagLength]; !found {
			return fmt.Errorf("unknown bit length for ecdsa")
		} else {
			pk, err = pki.NewPrivateKeyEcdsa(curve)
		}
	case "rsa":
		if RsaLowerLength > *flagLength || *flagLength > RsaUpperLength {
			return fmt.Errorf("bit length outside of range for rsa")
		}
		pk, err = pki.NewPrivateKeyRsa(int(*flagLength))
	default:
		return fmt.Errorf("unknown private key type")
	}

	return writePem(pk, out)
}
