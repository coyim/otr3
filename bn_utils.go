package otr3

import "math/big"

func modExp(g, x *big.Int) *big.Int {
	return new(big.Int).Exp(g, x, p)
}

func mul(l, r *big.Int) *big.Int {
	return new(big.Int).Mul(l, r)
}

func sub(l, r *big.Int) *big.Int {
	return new(big.Int).Sub(l, r)
}

func mulMod(l, r, m *big.Int) *big.Int {
	res := mul(l, r)
	res.Mod(res, m)
	return res
}

func subMod(l, r, m *big.Int) *big.Int {
	res := sub(l, r)
	res.Mod(res, m)
	return res
}

func mod(l, m *big.Int) *big.Int {
	return new(big.Int).Mod(l, m)
}
