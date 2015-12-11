package otr3

import (
	"bytes"
	"io"

	"github.com/agl/ed25519"
)

var ed25519KeyType = []byte{0x00, 0x03}
var ed25519KeyTypeValue = uint16(0x0003)

// Ed25519PublicKey is an Ed25519 public key
type Ed25519PublicKey struct {
	pub [ed25519.PublicKeySize]byte
}

// Ed25519PrivateKey is an Ed25519 private key
type Ed25519PrivateKey struct {
	Ed25519PublicKey
	priv [ed25519.PrivateKeySize]byte
}

// IsAvailableForVersion returns true if this key is possible to use with the given version
func (pub *Ed25519PublicKey) IsAvailableForVersion(v uint16) bool {
	return v == 4
}

// IsSame returns true if the given public key is an Ed2559 public key that is equal to this key
func (pub *Ed25519PublicKey) IsSame(other PublicKey) bool {
	oth, ok := other.(*Ed25519PublicKey)
	return ok && bytes.Equal(pub.pub[:], oth.pub[:])
}

// Fingerprint will generate a fingerprint of the serialized version of the key using the provided hash.
func (pub *Ed25519PublicKey) Fingerprint() []byte {
	b := pub.serialize()
	if b == nil {
		return nil
	}

	h := fingerprintHashInstanceForVersion(4)
	h.Write(b)
	return h.Sum(nil)
}

// PublicKey returns the public key corresponding to this private key
func (priv *Ed25519PrivateKey) PublicKey() PublicKey {
	return &priv.Ed25519PublicKey
}

// Parse takes the given data and tries to parse it into the PublicKey receiver. It will return not ok if the data is malformed or not for an Ed25519 key
func (pub *Ed25519PublicKey) Parse(in []byte) (index []byte, ok bool) {
	var typeTag uint16
	if index, typeTag, ok = extractShort(in); !ok || typeTag != ed25519KeyTypeValue {
		return in, false
	}
	var res []byte
	if index, res, ok = extractData(index); !ok {
		return in, false
	}
	copy(pub.pub[:], res)

	return
}

// Parse will parse a Private Key from the given data, by first parsing the public key components and then the private key component. It returns not ok for the same reasons as PublicKey.Parse.
func (priv *Ed25519PrivateKey) Parse(in []byte) (index []byte, ok bool) {
	if in, ok = priv.Ed25519PublicKey.Parse(in); !ok {
		return nil, false
	}

	var res []byte
	if index, res, ok = extractData(index); !ok {
		return in, false
	}
	copy(priv.priv[:], res)

	return index, ok
}

func (priv *Ed25519PrivateKey) serialize() []byte {
	result := priv.Ed25519PublicKey.serialize()
	return appendData(result, priv.priv[:])
}

// Serialize will return the serialization of the private key to a byte array
func (priv *Ed25519PrivateKey) Serialize() []byte {
	return priv.serialize()
}

func (pub *Ed25519PublicKey) serialize() []byte {
	return appendData(ed25519KeyType, pub.pub[:])
}

// Verify will verify a signature of a hashed data using ed25519 Verify.
func (pub *Ed25519PublicKey) Verify(message, sig []byte) (nextPoint []byte, sigOk bool) {
	if len(sig) < ed25519.SignatureSize {
		return nil, false
	}
	var tmpSig [ed25519.SignatureSize]byte
	copy(tmpSig[:], sig)
	ok := ed25519.Verify(&pub.pub, message, &tmpSig)
	return sig[ed25519.SignatureSize:], ok
}

// Sign will generate a signature of the message using ed25519 Sign.
func (priv *Ed25519PrivateKey) Sign(_ io.Reader, message []byte) ([]byte, error) {
	out := ed25519.Sign(&priv.priv, message)
	return out[:], nil
}

// Generate will generate a new Ed25519 Private Key with the randomness provided.
func (priv *Ed25519PrivateKey) Generate(rand io.Reader) error {
	pu, pr, err := ed25519.GenerateKey(rand)
	if err != nil {
		return err
	}

	copy(priv.priv[:], pr[:])
	copy(priv.pub[:], pu[:])

	return nil
}
