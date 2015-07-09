package otr3

import (
	"crypto/dsa"
	"io"
	"math/big"

	"github.com/twstrike/otr3/sexp"
)

type PublicKey struct {
	dsa.PublicKey
}

type PrivateKey struct {
	PublicKey
	dsa.PrivateKey
}

func readKey(data io.Reader) *PrivateKey {
	var pk PrivateKey
	pk.PrivateKey.P = bnFromHex("00FC07ABCF0DC916AFF6E9AE47BEF60C7AB9B4D6B2469E436630E36F8A489BE812486A09F30B71224508654940A835301ACC525A4FF133FC152CC53DCC59D65C30A54F1993FE13FE63E5823D4C746DB21B90F9B9C00B49EC7404AB1D929BA7FBA12F2E45C6E0A651689750E8528AB8C031D3561FECEE72EBB4A090D450A9B7A857")
	pk.PrivateKey.Q = bnFromHex("00997BD266EF7B1F60A5C23F3A741F2AEFD07A2081")
	return &pk
}

func readParameter(data io.Reader) (tag string, value *big.Int) {
	result := sexp.Parse(data)
	tag = result.First().String()
	val := result.Second().First().String()
	value, _ = new(big.Int).SetString(val[1:len(val)-1], 16)
	return
}
