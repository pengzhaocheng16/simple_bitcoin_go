package main

import (
	"fmt"
	"../blockchain_go"
	"github.com/ethereum/go-ethereum/common"
	"bytes"
)

func (cli *CLI) printChain(nodeID string) {
	bc := core.NewBlockchain(nodeID)
	defer bc.Db.Close()

	bci := bc.Iterator()

	for {
		block := bci.Next()

		fmt.Printf("============ Block %x ============\n", block.Hash)
		fmt.Printf("Height: %d\n", block.Height)
		fmt.Printf("Diffculty: %d\n", block.Difficulty)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Printf("Timestamp: %d\n", block.Timestamp)
		fmt.Printf("Prev. block: %x\n", block.PrevBlockHash)
		//pow := core.NewProofOfWork(block,block.Difficulty.Int64())
		//fmt.Printf("PoW: %s\n\n", strconv.FormatBool(pow.Validate()))
		for _, tx := range block.Transactions {
			fmt.Println(tx)
		}
		fmt.Printf("\n\n")

		if bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes())  {
			break
		}
	}
}
