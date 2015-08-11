package compat

import (
	"io"

	"github.com/twstrike/otr3"
)

// PublicKey represents an OTR Public Key
type PublicKey struct {
	otr3.PublicKey
}

// PrivateKey represents an OTR Private Key
type PrivateKey struct {
	otr3.PrivateKey
	PublicKey
}

// Generate will generate a new Private Key using the provided randomness
func (priv *PrivateKey) Generate(rand io.Reader) {
	if err := priv.PrivateKey.Generate(rand); err != nil {
		panic(err.Error())
	}
}

// Serialize will serialize the private key
func (priv *PrivateKey) Serialize(in []byte) []byte {
	return append(in, priv.PrivateKey.Serialize()...)
}

func (priv *PrivateKey) Sign(rand io.Reader, hashed []byte) []byte {
	ret, err := priv.PrivateKey.Sign(rand, hashed)
	if err != nil {
		panic(err)
	}

	return ret
}

// Fingerprint will generate a new SHA-1 fingerprint of the serialization of the public key
func (pub *PublicKey) Fingerprint() []byte {
	return pub.PublicKey.DefaultFingerprint()
}

func (priv *PrivateKey) Parse(in []byte) (index []byte, ok bool) {
	rest, ok := priv.PrivateKey.Parse(in)
	if !ok {
		return rest, ok
	}

	// wraps the PubKey embedded type in a compat.PubKey
	// This is necessary because x/crypto/otr implementation uses Fingerprint()
	// method through PrivateKey's embedded type PublicKey
	priv.PublicKey = PublicKey{priv.PrivateKey.PublicKey}

	return rest, ok
}
