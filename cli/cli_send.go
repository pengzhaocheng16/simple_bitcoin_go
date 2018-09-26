package main

import (
	"fmt"
	"log"
	"../blockchain_go"
	"../p2pprotocol"
	"time"
	"encoding/hex"
	"math/big"
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
	log.Println("--start cli send ")

	var bc *core.Blockchain
	bc = core.NewBlockchain(nodeID)

	UTXOSet := core.UTXOSet{bc}
	//defer bc.Db.Close()

	wallets, err := core.NewWallets(nodeID)
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet(from)

	tx := core.NewUTXOTransaction(&wallet, to, big.NewInt(int64(amount)),[]byte{}, &UTXOSet,nodeID)

	if mineNow {
		cbTx := core.NewCoinbaseTX(from, "",nodeID)
		txs := []*core.Transaction{cbTx, tx}

		newBlock := bc.MineBlock(txs)
		UTXOSet.Update(newBlock)
		bc.Db.Close()
	} else {
		bc.Db.Close()
		//remove comfirmed transaction vin txs from persistent tx queue
		// in confirmTx()
		//In case of double spend check fail need to store prev uncomfirmed transaction input tx
		core.PendingIn(nodeID,tx)
		address := wallet.ToCommonAddress().String()
		var wt = new(core.WalletTransactions)
		wt.InitDB(nodeID,address)
		wt.PutTransaction(tx.ID,tx.Serialize(),address)
		wt.DB.Close()
		go func(){
			if(p2pprotocol.CurrentNodeInfo == nil){
				p2pprotocol.StartServer(nodeID,"","","",0)
			}
		}()
		time.Sleep(2*time.Second)
		select{
			case ch := <- p2pprotocol.Manager.BestTd:

				bc1 := core.NewBlockchain(nodeID)
				td,_ := bc1.GetBestHeight()
				bc1.Db.Close()
				if(td.Cmp(ch) == 0){
					log.Println("---td:",ch)
					break
				}
		}
		//p2pprotocol.SendTx(core.BootNodes[0], tx)
		//go func(){
			for _, p := range p2pprotocol.Manager.Peers.Peers {
				p2pprotocol.SendTx(p, p.Rw, tx)
			}
			p2pprotocol.Manager.TxMempool[hex.EncodeToString(tx.ID)] = tx
		//}()
		//select{}
		for{
			var send,from,fromaddress,to,toaddress,amount string
			var amountnum int
			fmt.Scanf("%s %s %s %s %s %s %d", &send,&from,&fromaddress,&to,&toaddress,&amount,&amountnum)

			log.Println("--send ",send)
			if(send == ""||send != "send"){
				log.Panic("need send command")
			}
			if(from == ""||from != "-from"){
				log.Panic("need from command")
			}
			if(fromaddress == ""){
				log.Panic("need fromaddress param")
			}
			if(to == ""||to != "-to"){
				log.Panic("need to command")
			}
			if(toaddress == ""){
				log.Panic("need toaddress param")
			}
			if(amount == ""||amount != "-amount"){
				log.Panic("need amount command")
			}
			if(amountnum == 0){
				log.Panic("need amount  param")
			}

			bc = core.NewBlockchain(nodeID)
			UTXOSet := core.UTXOSet{bc}
			log.Println("--send to",toaddress)
			tx := core.NewUTXOTransaction(&wallet, toaddress, big.NewInt(int64(amountnum)), []byte{},&UTXOSet,nodeID)
			for _, p := range p2pprotocol.Manager.Peers.Peers {
				p2pprotocol.SendTx(p, p.Rw, tx)
			}
			p2pprotocol.Manager.TxMempool[hex.EncodeToString(tx.ID)] = tx
			bc.Db.Close()
			//cli.send(fromaddress,toaddress,amountnum,nodeID,false)
		}
	}

	//fmt.Println("Success!")
}
