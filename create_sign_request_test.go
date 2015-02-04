package main

import (
  "bytes"
  "crypto/x509"
  "encoding/pem"
  "io/ioutil"
  "net"
  "testing"
)

type CSRTest struct {
  ShouldBe []string
  Set      func(*SignFlags)
  Fetch    func(*x509.CertificateRequest) []string
}

const (
  RAW_PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MIHbAgEBBEFkAEFc5264Yo7Xo+yj3ZwaqdffTphGT3/8Q+pvi4ULmXaFiGoTkR5X
lKnlRUEp0I4Ra9U7GjLDtFLwTaLzdXuUT6AHBgUrgQQAI6GBiQOBhgAEAdW0usq0
zEzvhR0u5ZSbOXRzg+TbICZGfOLy9KpKfz6I6suFOAO7f3fwDNOqMfyYUhtenMz7
T/BKArg+v58UWHrwAb/UeI4l+OMOoMHYtNNO4nAjTdyY8yFSFY5syzKEYIBzUoLM
VSfuxBk5ZS2J478X1Vxacq03keDeAY43Oc80XBih
-----END EC PRIVATE KEY-----`
)

func SetupTest() (*SignFlags, *bytes.Buffer) {
  p, _ := pem.Decode([]byte(RAW_PRIVATE_KEY))
  buf := bytes.NewBuffer(make([]byte, 0))

  flags := &SignFlags{
    private_key: load_private_key_ecdsa(p),
    output_stream: buf,
  }
  return flags, buf
}

func TestCSRGeneration(t *testing.T) {
  tests := []CSRTest {
    {
      []string{"foo"},
      func(f *SignFlags) { f.BaseAttributes.CommonName = "foo" },
      func(c *x509.CertificateRequest) []string { return []string{c.Subject.CommonName} },
    }, {
      []string{"foo.com", "bar.com", "baz.com"},
      func(f *SignFlags) { f.DNSNames = []string{ "foo.com", "bar.com", "baz.com" }},
      func(c *x509.CertificateRequest) []string { return c.DNSNames },
    },
    {
      []string{"127.0.0.1", "192.168.0.1"},
      func(f *SignFlags) { f.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.0.1") }},
      func(c *x509.CertificateRequest) []string {
        res := make([]string, 0)
        for _, ip := range c.IPAddresses {
          res = append(res, ip.String())
        }
        return res
      },
    },
  }
  for _, test := range tests {
    flags, io := SetupTest()
    test.Set(flags)

    create_csr(*flags)
    res, _ := ioutil.ReadAll(io)
    raw, _ := pem.Decode(res)

    csr, _ := x509.ParseCertificateRequest(raw.Bytes)
    if !diff(test.ShouldBe, test.Fetch(csr)) {
      t.Logf("Expected: %v\nbut got: %v", test.ShouldBe, test.Fetch(csr))
      t.Fail()
    }
  }
}

func diff(a, b []string) bool {
  if len(a) != len(b) { return false }
  for i, e := range a {
    if e != b[i] { return false }
  }
  return true
}
