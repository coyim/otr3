package otr3

import "math/big"

type dhKeyPair struct {
	pub  *big.Int
	priv *big.Int
}

type keyManagementContext struct {
	ourKeyID, theirKeyID                        uint32
	ourCurrentDHKeys, ourPreviousDHKeys         dhKeyPair
	theirCurrentDHPubKey, theirPreviousDHPubKey *big.Int
}
