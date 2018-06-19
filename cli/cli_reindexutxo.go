package main

import (
	"fmt"
	"../blockchain_go"
)

func (cli *CLI) reindexUTXO(nodeID string) {
	bc := core.NewBlockchain(nodeID)
	defer bc.Db.Close()
	UTXOSet := core.UTXOSet{bc}
	UTXOSet.Reindex()

	count := UTXOSet.CountTransactions()
	fmt.Printf("Done! There are %d transactions in the UTXO set.\n", count)
}
