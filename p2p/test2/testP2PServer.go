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

	wallets, err := core.NewWallets("192.168.1.196:2000")
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet("1NWUWL17WtxzSMVWhGm8UD7Y45ikFUHZCx")

	peers := []*discover.Node{&discover.Node{IP: net.ParseIP("192.168.1.196"),TCP:30301,UDP:30301,ID: discover.PubkeyID(&wallet.PrivateKey.PublicKey)}}

	wallets1, err := core.NewWallets("192.168.1.196:2001")
	if err != nil {
		log.Panic(err)
	}
	wallet1 := wallets1.GetWallet("1EgyiGniMHR1jvu5T4xSP5J3QWLjNskc1D")
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
		//NAT:nat.Any(),
		//ListenAddr: "127.0.0.1:30301",
		ListenAddr: "192.168.1.196:30300",
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