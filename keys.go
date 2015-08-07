package otr3

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash"
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
	a.name, ok2 = readAccountName(r)
	a.protocol, ok3 = readAccountProtocol(r)
	a.key, ok4 = readPrivateKey(r)
	ok5 := sexp.ReadListEnd(r)
	return a, ok1 && ok2 && ok3 && ok4 && ok5, false
}

func readPrivateKey(r *bufio.Reader) (*PrivateKey, bool) {
	sexp.ReadListStart(r)
	ok1 := readSymbolAndExpect(r, "private-key")
	k := new(PrivateKey)
	res, ok2 := readDSAPrivateKey(r)
	if ok2 {
		k.PrivateKey = *res
		k.PublicKey.PublicKey = k.PrivateKey.PublicKey
	}
	ok3 := sexp.ReadListEnd(r)
	return k, ok1 && ok2 && ok3
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

// Parse takes the given data and tries to parse it into the PublicKey receiver. It will return not ok if the data is malformed or not for a DSA key
func (pub *PublicKey) Parse(in []byte) (index []byte, ok bool) {
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
func (priv *PrivateKey) Parse(in []byte) (index []byte, ok bool) {
	if in, ok = priv.PublicKey.Parse(in); !ok {
		return nil, false
	}

	priv.PrivateKey.PublicKey = priv.PublicKey.PublicKey
	index, priv.X, ok = extractMPI(in)

	return index, ok
}

var dsaKeyType = []byte{0x00, 0x00}
var dsaKeyTypeValue = uint16(0x0000)

func (priv *PrivateKey) serialize() []byte {
	result := priv.PublicKey.serialize()
	return appendMPI(result, priv.PrivateKey.X)
}

// Serialize will return the serialization of the private key to a byte array
func (priv *PrivateKey) Serialize() []byte {
	return priv.serialize()
}

func (pub *PublicKey) serialize() []byte {
	//TODO: Should this be an error?
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
func (pub *PublicKey) Fingerprint(h hash.Hash) []byte {
	b := pub.serialize()
	if b == nil {
		return nil
	}

	h.Write(b[2:]) // if public key is DSA, ignore the leading 0x00 0x00 for the key type (according to spec)
	return h.Sum(nil)
}

// DefaultFingerprint generates a fingerprint of the public key using SHA-1.
func (pub *PublicKey) DefaultFingerprint() []byte {
	return pub.Fingerprint(sha1.New())
}

func (priv *PrivateKey) sign(rand io.Reader, hashed []byte) ([]byte, error) {
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

func (pub *PublicKey) verify(hashed, sig []byte) (nextPoint []byte, sigOk bool) {
	if len(sig) < 2*20 {
		return nil, false
	}
	r := new(big.Int).SetBytes(sig[:20])
	s := new(big.Int).SetBytes(sig[20:40])
	ok := dsa.Verify(&pub.PublicKey, hashed, r, s)
	return sig[20*2:], ok
}

func counterEncipher(key, iv, src, dst []byte) error {
	aesCipher, err := aes.NewCipher(key)

	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(aesCipher, iv)
	ctr.XORKeyStream(dst, src)

	return nil
}

func encrypt(key, data []byte) (dst []byte, err error) {
	dst = make([]byte, len(data))
	err = counterEncipher(key, dst[:aes.BlockSize], data, dst)
	return
}

func decrypt(key, dst, src []byte) error {
	return counterEncipher(key, make([]byte, aes.BlockSize), src, dst)
}

// Import parses the contents of a libotr private key file.
func (priv *PrivateKey) Import(in []byte) bool {
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
	priv.PublicKey.PublicKey = priv.PrivateKey.PublicKey

	a := new(big.Int).Exp(priv.PrivateKey.G, priv.PrivateKey.X, priv.PrivateKey.P)
	return a.Cmp(priv.PrivateKey.Y) == 0
}

// Generate will generate a new DSA Private Key with the randomness provided. The parameter size used is 1024 and 160.
func (priv *PrivateKey) Generate(rand io.Reader) error {
	if err := dsa.GenerateParameters(&priv.PrivateKey.PublicKey.Parameters, rand, dsa.L1024N160); err != nil {
		return err
	}
	if err := dsa.GenerateKey(&priv.PrivateKey, rand); err != nil {
		return err
	}
	priv.PublicKey.PublicKey = priv.PrivateKey.PublicKey
	return nil
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

func exportPrivateKey(key *PrivateKey, w *bufio.Writer) {
	indent := "    "
	w.WriteString(indent)
	w.WriteString("(private-key\n")
	exportDSAPrivateKey(key, w)
	w.WriteString(indent)
	w.WriteString(")\n")
}

func exportDSAPrivateKey(key *PrivateKey, w *bufio.Writer) {
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

func exportParameter(name string, val *big.Int, w *bufio.Writer) {
	indent := "        "
	w.WriteString(indent)
	w.WriteString(fmt.Sprintf("(%s #%X#)\n", name, val))
}

func exportAccount(a *Account, w *bufio.Writer) {
	indent := "  "
	w.WriteString(indent)
	w.WriteString("(account\n")
	exportName(a.name, w)
	exportProtocol(a.protocol, w)
	exportPrivateKey(a.key, w)
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
