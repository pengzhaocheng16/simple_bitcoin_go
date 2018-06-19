package core

import (
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"bytes"
)

var (
	maxNonce = math.MaxInt64
)

const targetBits = 4

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.PrevBlockHash,
			pow.block.HashTransactions(),
			IntToHex(pow.block.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)

	return data
}

// Run performs a proof-of-work
func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte
	var data []byte
	nonce := 0

	fmt.Printf("Mining a new block")
	for nonce < maxNonce {
		data = pow.prepareData(nonce)

		hash = sha256.Sum256(data)
		fmt.Printf("\r%x", hash)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			fmt.Printf("newBlock.PrevBlockHash nonce %x \n",  sha256.Sum256(IntToHex(int64(nonce))))
			break
		} else {
			nonce = nonce+1
		}
	}
	/*
	for _, tx := range pow.block.Transactions {
		fmt.Printf("tx.input   %x \n", tx.Vin)
		fmt.Printf("tx.output   %x \n", tx.Vout)
		fmt.Printf("tx.id   %x \n", tx.ID)

		fmt.Printf("tx.Serialize   %x \n", tx.Serialize())
		fmt.Printf("tx.hash   %x \n", tx.Hash())
	}
	fmt.Printf("newBlock.PrevBlockHash %s \n", hex.EncodeToString(pow.block.PrevBlockHash[:]))
	fmt.Printf("newBlock.PrevBlockHash %s \n", hex.EncodeToString(pow.block.HashTransactions()))
	fmt.Printf("newBlock.PrevBlockHash %s \n", pow.block.Timestamp)
	fmt.Printf("newBlock.PrevBlockHash %s \n", int64(targetBits))
	fmt.Printf("newBlock.PrevBlockHash %s \n", int64(nonce))
	fmt.Printf("mined Blockdata len %n \n", len(data))
	*/
	fmt.Print("\n\n")

	return nonce, hash[:]
}

// Validate validates block's PoW
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int

	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	isValid := hashInt.Cmp(pow.target) == -1

	return isValid
}
