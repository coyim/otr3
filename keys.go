package otr3

import "crypto/dsa"

type PublicKey struct {
	dsa.PublicKey
}

type PrivateKey struct {
	PublicKey
	dsa.PrivateKey
}
