package main

import (
	"fmt"
	"log"
	"os"
	."../boltqueue"
	"../blockchain_go"
	"../p2pprotocol"
)

func (cli *CLI) send(from, to string, amount int, nodeID string, mineNow bool) {
	core.MineNow_ = mineNow
	if !core.ValidateAddress(from) {
		log.Panic("ERROR: Sender address is not valid")
	}
	if !core.ValidateAddress(to) {
		log.Panic("ERROR: Recipient address is not valid")
	}
	if from == to {
		log.Panic("ERROR: Wallet from equal Wallet to is not valid")
	}

	bc := core.NewBlockchain(nodeID)
	UTXOSet := core.UTXOSet{bc}
	//defer bc.db.Close()

	wallets, err := core.NewWallets(nodeID)
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet(from)

	tx := core.NewUTXOTransaction(&wallet, to, amount, &UTXOSet)
	//TODO remove comfirmed transaction from persistent queue
	//In case of double spend check fail need to store prev uncomfirmed transaction input tx
	if(!mineNow){
		queueFile := fmt.Sprintf("%x_tx.db", wallet.GetAddress())
		txPQueue, err := NewPQueue(queueFile)
		if err != nil {
			log.Panic("create queue error",err)
		}
		defer txPQueue.Close()
		defer os.Remove(queueFile)
		eqerr := txPQueue.Enqueue(1, NewMessageBytes(tx.Vin[0].Txid))
		if err != nil {
			log.Panic("Enqueue error",eqerr)
		}
	}

	if mineNow {
		cbTx := core.NewCoinbaseTX(from, "")
		txs := []*core.Transaction{cbTx, tx}

		newBlock := bc.MineBlock(txs)
		UTXOSet.Update(newBlock)
	} else {
		//p2pprotocol.SendTx(core.KnownNodes[0], tx)
		i := 1
		var p *p2pprotocol.Peer
		for _, v := range p2pprotocol.Peers {
			if(i<2){
				p = v
				break
			}
			i = i+1
		}
		p2pprotocol.SendTx(p.Rw, tx)
	}

	fmt.Println("Success!")
}
