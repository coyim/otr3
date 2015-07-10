package otr3

import (
	"bufio"
	"crypto/dsa"
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
	return readAccounts(bufio.NewReader(r))
}

func readSymbolAndExpect(r *bufio.Reader, s string) bool {
	res := sexp.ReadSymbol(r).Value().(string)
	return res == s
}

func assignParameter(k *dsa.PrivateKey, s string, v *big.Int) {
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
	sexp.ReadListStart(r)
	readSymbolAndExpect(r, "name")
	nm := sexp.ReadString(r).Value().(string)
	sexp.ReadListEnd(r)
	return nm
}

func readAccountProtocol(r *bufio.Reader) string {
	sexp.ReadListStart(r)
	readSymbolAndExpect(r, "protocol")
	nm := sexp.ReadSymbol(r).Value().(string)
	sexp.ReadListEnd(r)
	return nm
}

func readAccount(r *bufio.Reader) *Account {
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
	sexp.ReadListStart(r)
	readSymbolAndExpect(r, "private-key")
	k := new(PrivateKey)
	k.PrivateKey = *readDSAPrivateKey(r)
	sexp.ReadListEnd(r)
	return k
}

func readDSAPrivateKey(r *bufio.Reader) *dsa.PrivateKey {
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

func (pub *PublicKey) Parse(in []byte) int {
	//TODO Error handling
	//extractShort(in, 0)

	index := 2
	index, pub.P = extractMPI(in, index)
	index, pub.Q = extractMPI(in, index)
	index, pub.G = extractMPI(in, index)
	index, pub.Y = extractMPI(in, index)
	return index
}

func (priv *PrivateKey) Parse(in []byte) {
	//TODO Error handling
	//extractShort(in, 0)

	index := priv.PublicKey.Parse(in)
	index, priv.X = extractMPI(in, index)
}
