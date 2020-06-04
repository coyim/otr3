package constbn

import "math/big"

// Int represents an arbitrarily sized integer
type Int struct {
	v []base
}

// SetBigInt sets the value this int to the value in the big.Int
func (i *Int) SetBigInt(b *big.Int) *Int {
	return i.SetBytes(b.Bytes())
}

// GetBigInt returns a big.Int that represents the same value as this int
func (i *Int) GetBigInt() *big.Int {
	return new(big.Int).SetBytes(i.Bytes())
}

// SetBytes interprets buf as the bytes of a big-endian unsigned
// integer, sets z to that value, and returns z.
func (i *Int) SetBytes(b []byte) *Int {
	i.v = simpleDecode(b)
	return i
}

// Bytes returns the absolute value of x as a big-endian byte slice.
func (i *Int) Bytes() []byte {
	return simpleEncode(i.v)
}

// ExpB sets and returns the value x to the power of y, mod m.
// m has to be an odd number. y is the representation of a number
// in big-endian byte order. x has to be smaller than m.
func (i *Int) ExpB(x *Int, y []byte, m *Int) *Int {
	i.v = simpleModpowOpt(x.v, y, m.v)
	return i
}

// Exp sets and returns the value x to the power of y, mod m.
// m has to be an odd number. x has to be smaller than m.
func (i *Int) Exp(x, y, m *Int) *Int {
	yb := y.Bytes()
	return i.ExpB(x, yb, m)
}

// Set sets the value of the receiver to the argument
func (i *Int) Set(v *Int) *Int {
	i.Wipe()
	i.v = make([]base, len(v.v))
	copy(i.v, v.v)
	return i
}

// Wipe will delete the value inside this Int. It should not
// be used after this
func (i *Int) Wipe() {
	copy(i.v, zeroes(base(len(i.v))))
}
