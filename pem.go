package main

// handle the pem decoding of files

import (
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/gibheer/pki"
)

type (
	pemMap map[string][][]byte
)

// Return the content of a section from the pem part.
//
// To get this working, the section must only be contained one time and nothing
// but the wanted section must exist.
func getSectionFromPem(pems pemMap, label string) ([]byte, error) {
	if res, found := pems[label]; !found {
		return []byte{}, fmt.Errorf("could not find section '%s'", label)
	} else if len(res) > 1 {
		return []byte{}, fmt.Errorf("too many entries of type '%s'", label)
	} else {
		return res[0], nil
	}
}

// parse the content of a file into a map of pem decoded bodies
func parseFile(file io.Reader) (pemMap, error) {
	raw, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("file is empty")
	}
	return parsePem(raw)
}

// parse a pem encoded payload into a lookup map
//
// Returns a map of labels and content and the overall number of found items.
func parsePem(payload []byte) (pemMap, error) {
	res := pemMap{}
	rest := payload
	rest_len := len(rest)
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil && len(rest) == rest_len {
			return nil, fmt.Errorf("no pem encoding found")
		}
		res[block.Type] = append(res[block.Type], block.Bytes)
		rest_len = len(rest)
	}
	return res, nil
}

func writePem(o pki.Pemmer, w io.Writer) error {
	marsh_pem, err := o.MarshalPem()
	if err != nil {
		return err
	}

	_, err = marsh_pem.WriteTo(w)
	if err != nil {
		return err
	}
	return nil
}
