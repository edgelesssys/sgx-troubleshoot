//go:build testapp
// +build testapp

package main

import _ "embed"

var (
	//go:embed testapp_host
	testappHost []byte
	//go:embed enclave_debug.signed
	testappDebugEnclave []byte
	//go:embed enclave.signed
	testappProductionEnclave []byte
)
