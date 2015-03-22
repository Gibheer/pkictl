package main

import (
  "crypto"
  "encoding/base64"
  "fmt"
  "io"
  "io/ioutil"
  "math/big"
  "os"

  "github.com/gibheer/pki"
)

const (
  ErrorProgram int = iota
  ErrorFlagInput
  ErrorInput
)

var (
  EmptyByteArray = make([]byte, 0)
)

func main() {
  InitFlags()
  CmdRoot.Execute()
}

// create a new private key
func create_private_key(cmd *Command, args []string) {
  err := checkFlags(checkOutput, checkPrivateKeyGeneration)
  if err != nil {
    crash_with_help(cmd, ErrorFlagInput, "Flags invalid: %s", err)
  }

  var pk pki.Pemmer
  switch FlagPrivateKeyGeneration.Type {
    case "ecdsa": pk, err = pki.NewPrivateKeyEcdsa(FlagPrivateKeyGeneration.Curve)
    case "rsa": pk, err = pki.NewPrivateKeyRsa(FlagPrivateKeyGeneration.Size)
    default: crash_with_help(cmd, ErrorInput, "Unknown private key type '%s'", FlagPrivateKeyGeneration.Type)
  }
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error creating private key: %s", err) }
  marsh_pem, err := pk.MarshalPem()
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error when marshalling to pem: %s", err) }
  _, err = marsh_pem.WriteTo(FlagOutput)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error when writing output: %s", err) }
}

// create a public key derived from a private key
func create_public_key(cmd *Command, args []string) {
  err := checkFlags(checkPrivateKey, checkOutput)
  if err != nil {
    crash_with_help(cmd, ErrorFlagInput, "Flags invalid: %s", err)
  }

  var pub_key pki.Pemmer
  pub_key = FlagPrivateKey.Public()
  marsh_pem, err := pub_key.MarshalPem()
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error when marshalling to pem: %s", err) }
  _, err = marsh_pem.WriteTo(FlagOutput)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error when writing output: %s", err) }
}

// sign a message using he private key
func sign_input(cmd *Command, args []string) {
  err := checkFlags(checkPrivateKey, checkInput, checkOutput)
  if err != nil {
    crash_with_help(cmd, ErrorFlagInput, "Flags invalid: %s", err)
  }

  message, err := ioutil.ReadAll(FlagInput)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error reading input: %s", err) }
  signature, err := FlagPrivateKey.Sign(message, crypto.SHA256)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Could not compute signature: %s", err) }
  _, err = io.WriteString(FlagOutput, base64.StdEncoding.EncodeToString(signature))
  if err != nil { crash_with_help(cmd, ErrorProgram, "Could not write to output: %s", err) }

  // if we print to stderr, send a final line break to make the output nice
  if FlagOutput == os.Stdout {
    // we can ignore the result, as either Stdout did work or not
    _, _ = io.WriteString(FlagOutput, "\n")
  }
}

// verify a message using a signature and a public key
func verify_input(cmd *Command, args []string) {
  err := checkFlags(checkPrivateKey, checkInput, checkOutput, checkSignature)
  if err != nil {
    crash_with_help(cmd, ErrorFlagInput, "Flags invalid: %s", err)
  }

  signature := FlagSignature
  message, err := ioutil.ReadAll(FlagInput)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error reading input: %s", err) }
  valid, err := FlagPublicKey.Verify(message, signature, crypto.SHA256)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Could not verify message using signature: %s", err) }
  if valid {
    fmt.Println("valid")
    os.Exit(0)
  }
  fmt.Println("invalid")
  os.Exit(1)
}

// create a certificate sign request
func create_sign_request(cmd *Command, args []string) {
  err := checkFlags(checkPrivateKey, checkOutput, checkCertificateFields)
  if err != nil {
    crash_with_help(cmd, ErrorFlagInput, "Flags invalid: %s", err)
  }

  csr, err := FlagCertificateData.ToCertificateRequest(FlagPrivateKey)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Could not create certificate sign request: %s", err) }
  pem_block, err := csr.MarshalPem()
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error when marshalling to pem: %s", err) }
  _, err = pem_block.WriteTo(FlagOutput)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Could not write to output: %s", err) }
}

func create_cert(cmd *Command, args []string) {
  err := checkFlags(checkPrivateKey, checkOutput, checkCSR)
  if err != nil {
    crash_with_help(cmd, ErrorFlagInput, "Flags invalid: %s", err)
  }

  // TODO implement flags for all certificate options
  cert_opts := pki.CertificateOptions{}
  cert_opts.SerialNumber = big.NewInt(1)
  cert, err := FlagCertificateSignRequest.ToCertificate(
    FlagPrivateKey,
    cert_opts,
    nil,
  )
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error generating certificate: %s", err) }
  pem_block, err := cert.MarshalPem()
  if err != nil { crash_with_help(cmd, ErrorProgram, "Error when marshalling to pem: %s", err) }
  _, err = pem_block.WriteTo(FlagOutput)
  if err != nil { crash_with_help(cmd, ErrorProgram, "Could not write to output: %s", err) }
}

// crash and provide a helpful message
func crash_with_help(cmd *Command, code int, message string, args ...interface{}) {
  fmt.Fprintf(os.Stderr, message + "\n", args...)
  cmd.Usage()
  os.Exit(code)
}

// return the arguments to the program
func program_args() []string {
  return os.Args[2:]
}
