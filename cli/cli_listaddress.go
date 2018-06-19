package main

import (
	"fmt"
	"log"
	"../blockchain_go"
)

func (cli *CLI) listAddresses(nodeID string) {
	wallets, err := core.NewWallets(nodeID)
	if err != nil {
		log.Panic(err)
	}
	addresses := wallets.GetAddresses()

	for _, address := range addresses {
		fmt.Println(address)
	}
}
