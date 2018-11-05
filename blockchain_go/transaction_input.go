package core

import (
	"bytes"
	"math/big"
)

// TXInput represents a transaction input
type TXInput struct {
	Txid      []byte
	Vout      *big.Int
	Signature []byte
	PubKey    []byte
}

// UsesKey checks whether the address initiated the transaction
func (in *TXInput) UsesKey(pubKeyHash []byte) bool {
	lockingHash := HashPubKey256T(in.PubKey)

	return bytes.Compare(lockingHash, pubKeyHash) == 0
}
