pkictl
======

Pkictl can be used to manage the lifecycle of keys and certificates.

Its main purpose is the creation of certificates and control through rules of the
certification process. But it can also be used to sign and verify messages based
on private/public keys.

The focus is on easy commands with clear error messages to make work for the admin
or user as easy as possible. But it can also be used in scripts to implement
automated workflows.

features
--------

The following commnds will be implemented:

* create private key (RSA or ECDSA)
* create public key based on private key
* sign a message using a private key
* verify a message using a public key
* create a certificate sign request using a private key (WIP)
* create a certificate using a CSR (not implemented)
* show information about a CSR/private key/... (not implemented)
* verify certificate against rules and CSR (not implemented)

Installation
------------

To build pkictl Go 1.4 is required.

The project can be built with

    go get github.com/Gibheer/pkictl

which fetches all dependencies needed and builds the binary into your
$GOPATH/bin.

Usage
-----

### print all commands

To print all commands, use

    # ./pkictl
    Usage: pkictl command args
    where 'command' is one of:
        create-private    create a new private key
        create-public     create a public key from a private one
        create-cert-sign  create a new certificate sign request
        help              show this help
        info              get info on a file
        sign              sign a certificate request
        sign-input        sign a message with a private key
        verify-signature  verify a signature

Print the help for a command:

    ./pkictl create-public --help
    Usage of create-public:
      -output="STDOUT": path where the generated public key should be stored
      -private-key="": path to the private key file

Contributing
------------

The best way to contribute is to use [github.com/gibheer/pkictl](https://github.com/gibheer/pkictl).
