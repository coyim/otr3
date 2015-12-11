package otr3

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/twstrike/otr3/sexp"
)

// PublicKey is a public key used to verify signed messages
type PublicKey interface {
	Parse([]byte) ([]byte, bool)
	Fingerprint() []byte
	Verify([]byte, []byte) ([]byte, bool)

	serialize() []byte

	IsSame(PublicKey) bool
}

// PrivateKey is a private key used to sign messages
type PrivateKey interface {
	Parse([]byte) ([]byte, bool)
	Serialize() []byte
	Sign(io.Reader, []byte) ([]byte, error)
	Generate(io.Reader) error
	PublicKey() PublicKey
	IsAvailableForVersion(uint16) bool
}

// GenerateMissingKeys will look through the existing serialized keys and generate new keys to ensure that the functioning of this version of OTR will work correctly. It will only return the newly generated keys, not the old ones
func GenerateMissingKeys(existing [][]byte) ([]PrivateKey, error) {
	var result []PrivateKey
	hasDSA := false
	hasED := false

	for _, x := range existing {
		_, typeTag, ok := extractShort(x)
		if ok && typeTag == dsaKeyTypeValue {
			hasDSA = true
		}
		if ok && typeTag == ed25519KeyTypeValue {
			hasED = true
		}
	}

	if !hasDSA {
		var priv DSAPrivateKey
		if err := priv.Generate(rand.Reader); err != nil {
			return nil, err
		}
		result = append(result, &priv)
	}

	if !hasED {
		var priv Ed25519PrivateKey
		if err := priv.Generate(rand.Reader); err != nil {
			return nil, err
		}
		result = append(result, &priv)
	}

	return result, nil
}

// Account is a holder for the private key associated with an account
// It contains name, protocol and otr private key of an otr Account
type Account struct {
	Name     string
	Protocol string
	Key      PrivateKey
}

func readSymbolAndExpect(r *bufio.Reader, s string) bool {
	res, ok := readPotentialSymbol(r)
	return ok && res == s
}

func readPotentialBigNum(r *bufio.Reader) (*big.Int, bool) {
	res, _ := sexp.ReadValue(r)
	if res != nil {
		if tres, ok := res.(sexp.BigNum); ok {
			return tres.Value().(*big.Int), true
		}
	}
	return nil, false
}

func readPotentialSymbol(r *bufio.Reader) (string, bool) {
	res, _ := sexp.ReadValue(r)
	if res != nil {
		if tres, ok := res.(sexp.Symbol); ok {
			return tres.Value().(string), true
		}
	}
	return "", false
}

func readPotentialString(r *bufio.Reader) (string, bool) {
	res, _ := sexp.ReadValue(r)
	if res != nil {
		if tres, ok := res.(sexp.Sstring); ok {
			return tres.Value().(string), true
		}
	}
	return "", false
}

// ImportKeysFromFile will read the libotr formatted file given and return all accounts defined in it
func ImportKeysFromFile(fname string) ([]*Account, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ImportKeys(f)
}

// ExportKeysToFile will create the named file (or truncate it) and write all the accounts to that file in libotr format.
func ExportKeysToFile(acs []*Account, fname string) error {
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer f.Close()
	exportAccounts(acs, f)
	return nil
}

// ImportKeys will read the libotr formatted data given and return all accounts defined in it
func ImportKeys(r io.Reader) ([]*Account, error) {
	res, ok := readAccounts(bufio.NewReader(r))
	if !ok {
		return nil, newOtrError("couldn't import data into private key")
	}
	return res, nil
}

func readAccounts(r *bufio.Reader) ([]*Account, bool) {
	sexp.ReadListStart(r)
	ok1 := readSymbolAndExpect(r, "privkeys")
	ok2 := true
	var as []*Account
	for {
		a, ok, atEnd := readAccount(r)
		ok2 = ok2 && ok
		if atEnd {
			break
		}
		as = append(as, a)
	}
	ok3 := sexp.ReadListEnd(r)
	return as, ok1 && ok2 && ok3
}

func readAccountName(r *bufio.Reader) (string, bool) {
	sexp.ReadListStart(r)
	ok1 := readSymbolAndExpect(r, "name")
	nm, ok2 := readPotentialString(r)
	ok3 := sexp.ReadListEnd(r)
	return nm, ok1 && ok2 && ok3
}

func readAccountProtocol(r *bufio.Reader) (string, bool) {
	sexp.ReadListStart(r)
	ok1 := readSymbolAndExpect(r, "protocol")
	nm, ok2 := readPotentialSymbol(r)
	ok3 := sexp.ReadListEnd(r)
	return nm, ok1 && ok2 && ok3
}

func readAccount(r *bufio.Reader) (a *Account, ok bool, atEnd bool) {
	if !sexp.ReadListStart(r) {
		return nil, true, true
	}
	ok1 := readSymbolAndExpect(r, "account")
	a = new(Account)
	var ok2, ok3, ok4 bool
	a.Name, ok2 = readAccountName(r)
	a.Protocol, ok3 = readAccountProtocol(r)
	a.Key, ok4 = readPrivateKey(r)
	ok5 := sexp.ReadListEnd(r)
	return a, ok1 && ok2 && ok3 && ok4 && ok5, false
}

func readPrivateKey(r *bufio.Reader) (PrivateKey, bool) {
	sexp.ReadListStart(r)
	ok1 := readSymbolAndExpect(r, "private-key")
	k := new(DSAPrivateKey)
	res, ok2 := readDSAPrivateKey(r)
	if ok2 {
		k.PrivateKey = *res
		k.DSAPublicKey.PublicKey = k.PrivateKey.PublicKey
	}
	ok3 := sexp.ReadListEnd(r)
	return k, ok1 && ok2 && ok3
}

func readParameter(r *bufio.Reader) (tag string, value *big.Int, end bool, ok bool) {
	if !sexp.ReadListStart(r) {
		return "", nil, true, true
	}
	tag, ok1 := readPotentialSymbol(r)
	value, ok2 := readPotentialBigNum(r)
	ok = ok1 && ok2
	end = false
	if !sexp.ReadListEnd(r) {
		return "", nil, true, true
	}
	return
}

// ParsePrivateKey is an algorithm indepedent way of parsing private keys
func ParsePrivateKey(in []byte) (index []byte, ok bool, key PrivateKey) {
	var typeTag uint16
	index, typeTag, ok = extractShort(in)
	if !ok {
		return in, false, nil
	}

	switch typeTag {
	case dsaKeyTypeValue:
		key = &DSAPrivateKey{}
		index, ok = key.Parse(in)
		return
	case ed25519KeyTypeValue:
		key = &Ed25519PrivateKey{}
		index, ok = key.Parse(in)
		return
	}

	return in, false, nil
}

// ParsePublicKey is an algorithm independent way of parsing public keys
func ParsePublicKey(in []byte) (index []byte, ok bool, key PublicKey) {
	var typeTag uint16
	index, typeTag, ok = extractShort(in)
	if !ok {
		return in, false, nil
	}

	switch typeTag {
	case dsaKeyTypeValue:
		key = &DSAPublicKey{}
		index, ok = key.Parse(in)
		return
	case ed25519KeyTypeValue:
		key = &Ed25519PublicKey{}
		index, ok = key.Parse(in)
		return
	}

	return in, false, nil
}

func notHex(r rune) bool {
	if r >= '0' && r <= '9' ||
		r >= 'a' && r <= 'f' ||
		r >= 'A' && r <= 'F' {
		return false
	}

	return true
}

func exportName(n string, w *bufio.Writer) {
	indent := "    "
	w.WriteString(indent)
	w.WriteString("(name \"")
	w.WriteString(n)
	w.WriteString("\")\n")
}

func exportProtocol(n string, w *bufio.Writer) {
	indent := "    "
	w.WriteString(indent)
	w.WriteString("(protocol ")
	w.WriteString(n)
	w.WriteString(")\n")
}

func exportPrivateKey(key PrivateKey, w *bufio.Writer) {
	indent := "    "
	w.WriteString(indent)
	w.WriteString("(private-key\n")
	exportDSAPrivateKey(key.(*DSAPrivateKey), w)
	w.WriteString(indent)
	w.WriteString(")\n")
}

func exportParameter(name string, val *big.Int, w *bufio.Writer) {
	indent := "        "
	w.WriteString(indent)
	w.WriteString(fmt.Sprintf("(%s #%X#)\n", name, val))
}

func exportAccount(a *Account, w *bufio.Writer) {
	indent := "  "
	w.WriteString(indent)
	w.WriteString("(account\n")
	exportName(a.Name, w)
	exportProtocol(a.Protocol, w)
	exportPrivateKey(a.Key, w)
	w.WriteString(indent)
	w.WriteString(")\n")
}

func exportAccounts(as []*Account, w io.Writer) {
	bw := bufio.NewWriter(w)
	bw.WriteString("(privkeys\n")
	for _, a := range as {
		exportAccount(a, bw)
	}
	bw.WriteString(")\n")
	bw.Flush()
}
