package main

import (
	"fmt"
	"log"
	"../blockchain_go"
)

func (cli *CLI) createBlockchain(address, nodeID string) {
	if !core.ValidateAddress(address) {
		log.Panic("ERROR: Address is not valid")
	}
	bc := core.CreateBlockchain(address, nodeID)
	defer bc.Db.Close()

	UTXOSet := core.UTXOSet{bc}
	UTXOSet.Reindex()

	fmt.Println("Done!")
}
