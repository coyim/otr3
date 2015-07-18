package otr3

import (
	"bufio"
	"crypto/dsa"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"math/big"
	"os"

	"github.com/twstrike/otr3/sexp"
)

// PublicKey is a public key used to verify signed messages
type PublicKey struct {
	dsa.PublicKey
}

// PrivateKey is a private key used to sign messages
type PrivateKey struct {
	PublicKey
	dsa.PrivateKey
}

// Account is a holder for the private key associated with an account
type Account struct {
	name     string
	protocol string
	key      *PrivateKey
}

// ImportKeysFromFile will read the libotr formatted file given and return all accounts defined in it
func ImportKeysFromFile(fname string) ([]*Account, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ImportKeys(f), nil
}

// ImportKeys will read the libotr formatted data given and return all accounts defined in it
func ImportKeys(r io.Reader) []*Account {
	// TODO: errors?
	return readAccounts(bufio.NewReader(r))
}

func readSymbolAndExpect(r *bufio.Reader, s string) bool {
	res := sexp.ReadSymbol(r).Value().(string)
	return res == s
}

func assignParameter(k *dsa.PrivateKey, s string, v *big.Int) {
	// TODO: errors?
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
	}
}

func readAccounts(r *bufio.Reader) []*Account {
	// TODO: errors?
	sexp.ReadListStart(r)
	readSymbolAndExpect(r, "privkeys")
	var as []*Account
	for {
		a := readAccount(r)
		if a == nil {
			break
		}
		as = append(as, a)
	}
	sexp.ReadListEnd(r)
	return as
}

func readAccountName(r *bufio.Reader) string {
	// TODO: errors?
	sexp.ReadListStart(r)
	readSymbolAndExpect(r, "name")
	nm := sexp.ReadString(r).Value().(string)
	sexp.ReadListEnd(r)
	return nm
}

func readAccountProtocol(r *bufio.Reader) string {
	// TODO: errors?
	sexp.ReadListStart(r)
	readSymbolAndExpect(r, "protocol")
	nm := sexp.ReadSymbol(r).Value().(string)
	sexp.ReadListEnd(r)
	return nm
}

func readAccount(r *bufio.Reader) *Account {
	// TODO: errors?
	if !sexp.ReadListStart(r) {
		return nil
	}
	if !readSymbolAndExpect(r, "account") {
		return nil
	}
	a := new(Account)
	a.name = readAccountName(r)
	a.protocol = readAccountProtocol(r)
	a.key = readPrivateKey(r)
	if !sexp.ReadListEnd(r) {
		return nil
	}
	return a
}

func readPrivateKey(r *bufio.Reader) *PrivateKey {
	// TODO: errors?
	sexp.ReadListStart(r)
	readSymbolAndExpect(r, "private-key")
	k := new(PrivateKey)
	k.PrivateKey = *readDSAPrivateKey(r)
	sexp.ReadListEnd(r)
	return k
}

func readDSAPrivateKey(r *bufio.Reader) *dsa.PrivateKey {
	// TODO: errors?
	sexp.ReadListStart(r)
	readSymbolAndExpect(r, "dsa")
	k := new(dsa.PrivateKey)
	for {
		tag, value, end := readParameter(r)
		if end {
			break
		}
		assignParameter(k, tag, value)
	}
	sexp.ReadListEnd(r)
	return k
}

func readParameter(r *bufio.Reader) (tag string, value *big.Int, end bool) {
	// TODO: errors?
	if !sexp.ReadListStart(r) {
		return "", nil, true
	}
	tag = sexp.ReadSymbol(r).Value().(string)
	value = sexp.ReadBigNum(r).Value().(*big.Int)
	end = false
	if !sexp.ReadListEnd(r) {
		return "", nil, true
	}
	return
}

func (pub *PublicKey) parse(in []byte) int {
	//TODO Error handling
	//extractShort(in, 0)

	index := 2
	index, pub.P = extractMPI(in, index)
	index, pub.Q = extractMPI(in, index)
	index, pub.G = extractMPI(in, index)
	index, pub.Y = extractMPI(in, index)
	return index
}

func (priv *PrivateKey) parse(in []byte) {
	//TODO Error handling

	index := priv.PublicKey.parse(in)
	priv.PrivateKey.PublicKey = priv.PublicKey.PublicKey
	index, priv.X = extractMPI(in, index)
}

func parseIntoPrivateKey(hexString string) *PrivateKey {
	// TODO handle errors if ever used outside of tests
	b, _ := hex.DecodeString(hexString)
	var pk PrivateKey
	pk.parse(b)
	return &pk
}

var dsaKeyType = []byte{0x00, 0x00}

func (priv *PrivateKey) serialize() []byte {
	// TODO: errors?
	result := priv.PublicKey.serialize()
	return appendMPI(result, priv.PrivateKey.X)
}

func (pub *PublicKey) serialize() []byte {
	result := dsaKeyType
	result = appendMPI(result, pub.P)
	result = appendMPI(result, pub.Q)
	result = appendMPI(result, pub.G)
	result = appendMPI(result, pub.Y)
	return result
}

func (pub *PublicKey) fingerprint() []byte {
	// TODO: errors?
	b := pub.serialize()
	h := sha1.New() // TODO: this instance should be configurable
	h.Write(b[2:])  // if public key is DSA, ignore the leading 0x00 0x00 for the key type (according to spec)
	return h.Sum(nil)
}

func (priv *PrivateKey) sign(rand io.Reader, hashed []byte) ([]byte, error) {
	// TODO: errors?
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

func (pub *PublicKey) verify(hashed, sig []byte) ([]byte, bool) {
	// TODO: errors?
	if len(sig) != 2*20 {
		return nil, false
	}
	r := new(big.Int).SetBytes(sig[:20])
	s := new(big.Int).SetBytes(sig[20:])
	ok := dsa.Verify(&pub.PublicKey, hashed, r, s)
	return sig[20*2:], ok
}
