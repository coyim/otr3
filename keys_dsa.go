package otr3

import (
	"bufio"
	"bytes"
	"crypto/dsa"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/twstrike/otr3/sexp"
)

var dsaKeyType = []byte{0x00, 0x00}
var dsaKeyTypeValue = uint16(0x0000)

// DSAPublicKey is a DSA public key
type DSAPublicKey struct {
	dsa.PublicKey
}

// DSAPrivateKey is a DSA private key
type DSAPrivateKey struct {
	DSAPublicKey
	dsa.PrivateKey
}

func readDSAPrivateKey(r *bufio.Reader) (*dsa.PrivateKey, bool) {
	sexp.ReadListStart(r)
	ok1 := readSymbolAndExpect(r, "dsa")
	k := new(dsa.PrivateKey)
	for {
		tag, value, end, ok := readParameter(r)
		if !ok {
			return nil, false
		}
		if end {
			break
		}
		if !assignParameter(k, tag, value) {
			return nil, false
		}
	}
	ok2 := sexp.ReadListEnd(r)
	return k, ok1 && ok2
}

// IsAvailableForVersion returns true if this key is possible to use with the given version
func (pub *DSAPublicKey) IsAvailableForVersion(v uint16) bool {
	return v == 2 || v == 3
}

// IsSame returns true if the given public key is a DSA public key that is equal to this key
func (pub *DSAPublicKey) IsSame(other PublicKey) bool {
	oth, ok := other.(*DSAPublicKey)
	return ok && pub == oth
}

// Parse takes the given data and tries to parse it into the PublicKey receiver. It will return not ok if the data is malformed or not for a DSA key
func (pub *DSAPublicKey) Parse(in []byte) (index []byte, ok bool) {
	var typeTag uint16
	if index, typeTag, ok = extractShort(in); !ok || typeTag != dsaKeyTypeValue {
		return in, false
	}
	if index, pub.P, ok = extractMPI(index); !ok {
		return in, false
	}
	if index, pub.Q, ok = extractMPI(index); !ok {
		return in, false
	}
	if index, pub.G, ok = extractMPI(index); !ok {
		return in, false
	}
	if index, pub.Y, ok = extractMPI(index); !ok {
		return in, false
	}
	return
}

// Parse will parse a Private Key from the given data, by first parsing the public key components and then the private key component. It returns not ok for the same reasons as PublicKey.Parse.
func (priv *DSAPrivateKey) Parse(in []byte) (index []byte, ok bool) {
	if in, ok = priv.DSAPublicKey.Parse(in); !ok {
		return nil, false
	}

	priv.PrivateKey.PublicKey = priv.DSAPublicKey.PublicKey
	index, priv.X, ok = extractMPI(in)

	return index, ok
}

func (priv *DSAPrivateKey) serialize() []byte {
	result := priv.DSAPublicKey.serialize()
	return appendMPI(result, priv.PrivateKey.X)
}

// Serialize will return the serialization of the private key to a byte array
func (priv *DSAPrivateKey) Serialize() []byte {
	return priv.serialize()
}

func (pub *DSAPublicKey) serialize() []byte {
	if pub.P == nil || pub.Q == nil || pub.G == nil || pub.Y == nil {
		return nil
	}

	result := dsaKeyType
	result = appendMPI(result, pub.P)
	result = appendMPI(result, pub.Q)
	result = appendMPI(result, pub.G)
	result = appendMPI(result, pub.Y)
	return result
}

// Fingerprint will generate a fingerprint of the serialized version of the key using the provided hash.
func (pub *DSAPublicKey) Fingerprint() []byte {
	b := pub.serialize()
	if b == nil {
		return nil
	}

	h := fingerprintHashInstanceForVersion(3)

	h.Write(b[2:]) // if public key is DSA, ignore the leading 0x00 0x00 for the key type (according to spec)
	return h.Sum(nil)
}

// Sign will generate a signature of a hashed data using dsa Sign.
func (priv *DSAPrivateKey) Sign(rand io.Reader, hashed []byte) ([]byte, error) {
	r, s, err := dsa.Sign(rand, &priv.PrivateKey, hashed)
	if err == nil {
		rBytes := r.Bytes()
		sBytes := s.Bytes()

		out := make([]byte, 40)
		copy(out[20-len(rBytes):], rBytes)
		copy(out[len(out)-len(sBytes):], sBytes)
		return out, nil
	}
	return nil, err
}

// Verify will verify a signature of a hashed data using dsa Verify.
func (pub *DSAPublicKey) Verify(hashed, sig []byte) (nextPoint []byte, sigOk bool) {
	if len(sig) < 2*20 {
		return nil, false
	}
	r := new(big.Int).SetBytes(sig[:20])
	s := new(big.Int).SetBytes(sig[20:40])
	ok := dsa.Verify(&pub.PublicKey, hashed, r, s)
	return sig[20*2:], ok
}

// Import parses the contents of a libotr private key file.
func (priv *DSAPrivateKey) Import(in []byte) bool {
	mpiStart := []byte(" #")

	mpis := make([]*big.Int, 5)

	for i := 0; i < len(mpis); i++ {
		start := bytes.Index(in, mpiStart)
		if start == -1 {
			return false
		}
		in = in[start+len(mpiStart):]
		end := bytes.IndexFunc(in, notHex)
		if end == -1 {
			return false
		}
		hexBytes := in[:end]
		in = in[end:]

		if len(hexBytes)&1 != 0 {
			return false
		}

		mpiBytes := make([]byte, len(hexBytes)/2)
		if _, err := hex.Decode(mpiBytes, hexBytes); err != nil {
			return false
		}

		mpis[i] = new(big.Int).SetBytes(mpiBytes)
	}

	priv.PrivateKey.P = mpis[0]
	priv.PrivateKey.Q = mpis[1]
	priv.PrivateKey.G = mpis[2]
	priv.PrivateKey.Y = mpis[3]
	priv.PrivateKey.X = mpis[4]
	priv.DSAPublicKey.PublicKey = priv.PrivateKey.PublicKey

	a := new(big.Int).Exp(priv.PrivateKey.G, priv.PrivateKey.X, priv.PrivateKey.P)
	return a.Cmp(priv.PrivateKey.Y) == 0
}

// Generate will generate a new DSA Private Key with the randomness provided. The parameter size used is 1024 and 160.
func (priv *DSAPrivateKey) Generate(rand io.Reader) error {
	if err := dsa.GenerateParameters(&priv.PrivateKey.PublicKey.Parameters, rand, dsa.L1024N160); err != nil {
		return err
	}
	if err := dsa.GenerateKey(&priv.PrivateKey, rand); err != nil {
		return err
	}
	priv.DSAPublicKey.PublicKey = priv.PrivateKey.PublicKey
	return nil
}

// PublicKey returns the public key corresponding to this private key
func (priv *DSAPrivateKey) PublicKey() PublicKey {
	return &priv.DSAPublicKey
}

func exportDSAPrivateKey(key *DSAPrivateKey, w *bufio.Writer) {
	indent := "      "
	w.WriteString(indent)
	w.WriteString("(dsa\n")
	exportParameter("p", key.PrivateKey.P, w)
	exportParameter("q", key.PrivateKey.Q, w)
	exportParameter("g", key.PrivateKey.G, w)
	exportParameter("y", key.PrivateKey.Y, w)
	exportParameter("x", key.PrivateKey.X, w)
	w.WriteString(indent)
	w.WriteString(")\n")
}

func assignParameter(k *dsa.PrivateKey, s string, v *big.Int) bool {
	switch s {
	case "g":
		k.G = v
	case "p":
		k.P = v
	case "q":
		k.Q = v
	case "x":
		k.X = v
	case "y":
		k.Y = v
	default:
		return false
	}
	return true
}
