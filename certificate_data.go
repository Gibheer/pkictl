package main

import (
  "crypto/x509"
  "crypto/x509/pkix"
  "net"
)

type (
  certificateData struct {
    Subject  pkix.Name

    DnsNames       []string
    EmailAddresses []string
    IpAddresses    []net.IP
  }
)

func (c *certificateData) GenerateCSR() *x509.CertificateRequest {
  csr := &x509.CertificateRequest{}

  csr.Subject        = c.Subject
  csr.DNSNames       = c.DnsNames
  csr.IPAddresses    = c.IpAddresses
  csr.EmailAddresses = c.EmailAddresses

  return csr
}
