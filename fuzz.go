// +build gofuzz

package hashauth

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"os"
)

var (
	sampleKey    = []byte("sample key")
	samplePinKey = []byte("sample pin key")
	samplePinLen = 7
)

type sessionType struct {
	UserID int
	Admin  bool
}

// Fuzz is the entrypoint for go-fuzz to test the code here.
func Fuzz(data []byte) int {
	found := false

	for _, hasher := range []func() hash.Hash{
		md5.New,
		sha1.New,
		sha256.New,
		sha512.New,
	} {
		ha := New(sampleKey, &Options{
			Hash:       hasher,
			PINSignKey: samplePinKey,
			PINLength:  samplePinLen,
		})

		if ha.Validate(data) {
			found = true
		}

		if ha.Decode(data, &sessionType{}) == nil {
			found = true
		}

		pin, err := ha.Pin(data)
		if err != nil {
			// Pin() should always succeed
			os.Exit(1)
		}

		if ha.CheckPin(pin, data) {
			found = true
		}
	}

	if found {
		return 1
	}
	return 0
}
