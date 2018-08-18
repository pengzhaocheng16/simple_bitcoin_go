package core

import (
	"log"

	"github.com/boltdb/bolt"
	"github.com/ethereum/go-ethereum/common"
)

// BlockchainIterator is used to iterate over blockchain blocks
type BlockchainIterator struct {
	currentHash common.Hash
	db          *bolt.DB
}

// Next returns next block starting from the tip
func (i *BlockchainIterator) Next() *Block {
	var block *Block

	err := i.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		//fmt.Println("currentHash ",i.currentHash)
		encodedBlock := b.Get(i.currentHash.Bytes())
		//fmt.Println("len encodedBlock ",len(encodedBlock))
		block = DeserializeBlock(encodedBlock)

		return nil
	})

	if err != nil {
		log.Panic(err)
	}

	i.currentHash = block.PrevBlockHash

	return block
}
