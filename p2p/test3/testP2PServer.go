package main

import (
	"fmt"
	"os"
	"log"
	//"github.com/ethereum/go-ethereum/crypto"
	//"github.com/ethereum/go-ethereum/p2p"
	"../../p2p"
	"../../blockchain_go"
	"../../p2p/discover"
	"net"
)

const messageId = 0

type Message struct{Data string}
//type Message string

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

	wallets, err := core.NewWallets("192.168.1.196:2001")
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet("1EgyiGniMHR1jvu5T4xSP5J3QWLjNskc1D")

	peers := []*discover.Node{&discover.Node{IP: net.ParseIP("192.168.1.196"),TCP:30300,UDP:30300,ID: discover.PubkeyID(&wallet.PrivateKey.PublicKey)}}

	wallets1, err := core.NewWallets("192.168.1.196:3002")
	if err != nil {
		log.Panic(err)
	}
	wallet1 := wallets1.GetWallet("16pvA9cvhKjkn3inc2jXan6aK5M63LJ4Mz")
	nodekey := &wallet1.PrivateKey

	fmt.Println("nodekey:", nodekey)
	fmt.Println(" Curve:", nodekey.Curve == wallet.PrivateKey.Curve)
	fmt.Println(" PublicKey Curve:", nodekey.PublicKey.Curve == wallet.PrivateKey.PublicKey.Curve)

	config := p2p.Config{
		MaxPeers:   10,
		PrivateKey: nodekey,
		NoDiscovery:     false,
		Name:       "my node name",
		BootstrapNodes:peers,
		EnableMsgEvents:true,
		//NAT:nat.Any(),
		//ListenAddr: "127.0.0.1:30301",
		ListenAddr: "192.168.1.196:30302",
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
	//errc1 := make(chan error, 2)
	//errc1 <- p2p.Send(ws, 1,"foo")
	for {
		msg, err := ws.ReadMsg()
		if err != nil {
			return err
		}

		var myMessage Message
		err = msg.Decode(&myMessage)
		if err != nil {
			// handle decode error
			fmt.Println("3----------->msg.Decode(:", err)
			continue
		}

		switch myMessage.Data {
		case "foo":
			var message1 = Message{"bar"}
			err := p2p.SendItems(ws, messageId, &message1)
			if err != nil {
				return err
			}
			fmt.Println("3foo----------->recv:", myMessage.Data)
		default:
			fmt.Println("3----------->recv:", myMessage.Data)
		}
	}

	return nil
}