package main

import (
	"fmt"
	"io"
	"os"
)

// Open a path for writing
func openOutput(path string) (io.WriteCloser, error) {
	var (
		err error
		out io.WriteCloser
	)
	if path == "stdout" {
		out = os.Stdout
	} else {
		out, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0700)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Open a path for reading the content
func openInput(path string) (io.ReadCloser, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path is invalid")
	}
	var err error
	var in io.ReadCloser
	if path == "stdin" {
		in = os.Stdin
	} else {
		in, err = os.Open(path)
	}
	return in, err
}
