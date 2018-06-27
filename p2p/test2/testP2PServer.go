package main

import (
	"fmt"
	"os"
	"log"
	"net"
	//"github.com/ethereum/go-ethereum/p2p"
	//"github.com/ethereum/go-ethereum/p2p/discover"
	//"github.com/ethereum/go-ethereum/p2p/nat"
	//"github.com/ethereum/go-ethereum/crypto"
	"../../p2p"
	"../../blockchain_go"
	"../../p2p/discover"
	"../../p2p/nat"
)

const (
	messageId = 0
	// maxQueuedTxs is the maximum number of transaction lists to queue up before
	// dropping broadcasts. This is a sensitive number as a transaction list might
	// contain a single transaction, or thousands.
	maxQueuedTxs = 128

	// maxQueuedProps is the maximum number of block propagations to queue up before
	// dropping broadcasts. There's not much point in queueing stale blocks, so a few
	// that might cover uncles should be enough.
	maxQueuedProps = 4

	// maxQueuedAnns is the maximum number of block announcements to queue up before
	// dropping broadcasts. Similarly to block propagations, there's no point to queue
	// above some healthy uncle limit, so use that.
	maxQueuedAnns = 4

	// Protocol messages belonging to eth/62
	StatusMsg          = 0x00
)

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
		EnableMsgEvents:true,
		NAT:nat.Any(),
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
	//var myMessage = Message{data:"foo"}
	/*go func() {
		for {
			//errc1 := make(chan error, 2)
			errc1 :=  p2p.Send(ws, StatusMsg, &myMessage)
			if(errc1!=nil) {
				log.Panic(errc1)
				//fmt.Println("~~~~~p2p.Send:", errc1)
			}
		}
	}()*/
	var myMessage Message
	for {
		msg, err := ws.ReadMsg()
		if err != nil {
			return err
		}

		fmt.Println("-----------> ws.ReadMsg(:", msg.Payload)
		err = msg.Decode(&myMessage)
		if err != nil {
			fmt.Println("-----p.rw.ReadMsg:", err)
			// handle decode error
			continue
		}

		switch myMessage.Data {
		case "foo":
			go func() {
				message1 := Message{Data: "bar43443"}//Message("bar43443")
				err := p2p.SendItems(ws, StatusMsg, &message1)

				message2 := Message{Data: "bar11111"}//Message("bar11111")
				err = p2p.SendItems(ws, StatusMsg, &message2)
				if err != nil {
					fmt.Println("bar----------->p2p.SendItems(:", err)
					log.Panic(err)
					return
				}
			}()
			fmt.Println("foo----------->recv:", myMessage)
		default:
			fmt.Println("1----------->recv:", myMessage)
		}
	}

	return nil
}