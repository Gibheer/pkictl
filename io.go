package main

// handle all io and de/encoding of data

import (
  "encoding/pem"
  "errors"
  "io/ioutil"
)

var (
  ErrBlockNotFound = errors.New("block not found")
)

// load a pem section from a file
func readSectionFromFile(path, btype string) ([]byte, error) {
  raw, err := readFile(path)
  if err != nil { return raw, err }

  return decodeSection(raw, btype)
}

// read a file completely and report possible errors
func readFile(path string) ([]byte, error) {
  raw, err := ioutil.ReadFile(path)
  if err != nil { return EmptyByteArray, err }
  return raw, nil
}

// decode a pem encoded file and search for the specified section
func decodeSection(data []byte, btype string) ([]byte, error) {
  rest := data
  for len(rest) > 0 {
    var block *pem.Block
    block, rest = pem.Decode(rest)
    if block.Type == btype {
      return block.Bytes, nil
    }
  }
  return EmptyByteArray, ErrBlockNotFound
}
