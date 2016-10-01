package main

import (
	"fmt"
	"net"
	"strings"
)

type (
	ipList     []net.IP
	stringList []string
)

// return list of IPs as comma separated list
func (il *ipList) String() string {
	var res string
	list := ([]net.IP)(*il)
	for i := range list {
		if i > 0 {
			res += ", "
		}
		res += list[i].String()
	}
	return res
}

// receive multiple ip lists as comma separated strings
func (il *ipList) Set(value string) error {
	if len(value) == 0 {
		return nil
	}
	var ip net.IP

	parts := strings.Split(value, ",")
	for i := range parts {
		ip = net.ParseIP(strings.Trim(parts[i], " \t"))
		if ip == nil {
			// TODO encapsulate error in meaningfull error
			return fmt.Errorf("not a valid IP")
		}
		*il = append(*il, ip)
	}
	return nil
}

// return string list as a comma separated list
func (al *stringList) String() string {
	return strings.Join(([]string)(*al), ", ")
}

// receive multiple string lists as comma separated strings
func (al *stringList) Set(value string) error {
	if len(value) == 0 {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		*al = append(*al, strings.Trim(parts[i], " \t"))
	}
	return nil
}
