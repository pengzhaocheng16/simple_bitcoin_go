package main

import (
	"fmt"
	"os"
	"log"
	//"github.com/ethereum/go-ethereum/crypto"
	//"github.com/ethereum/go-ethereum/p2p"
	"../../p2p"
	"../../blockchain_go"
)

const messageId = 0

type Message string

func MyProtocol() p2p.Protocol {
	return p2p.Protocol{
		Name:    "MyProtocol",
		Version: 1,
		Length:  1,
		Run:     msgHandler,
	}
}

func main() {
	//nodekey, _ := crypto.GenerateKey()
	wallets, err := core.NewWallets("localhost:2000")
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet("1DSEDZ1XPkpW9yJQUZeRVU2EdRZ81c2mPa")
	nodekey := &wallet.PrivateKey
	//fmt.Println("nodekey:", nodekey)
	config := p2p.Config{
		MaxPeers:   10,
		PrivateKey: nodekey,
		NoDiscovery:     false,
		Name:       "my node name",
		//NAT:nat.Any(),
		//ListenAddr: "127.0.0.1:30301",
		ListenAddr: "192.168.1.196:30301",
		Protocols:  []p2p.Protocol{MyProtocol()},
	}
	srv := p2p.Server{Config: config}

	if err := srv.Start(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	select {}
}

func msgHandler(peer *p2p.Peer, ws p2p.MsgReadWriter) error {
	for {
		msg, err := ws.ReadMsg()
		if err != nil {
			return err
		}

		var myMessage Message
		err = msg.Decode(&myMessage)
		if err != nil {
			// handle decode error
			continue
		}

		switch myMessage {
		case "foo":
			err := p2p.SendItems(ws, messageId, "bar")
			if err != nil {
				return err
			}
		default:
			fmt.Println("recv:", myMessage)
		}
	}

	return nil
}