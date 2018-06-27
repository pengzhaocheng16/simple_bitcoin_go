package main

import (
	"fmt"
	"os"
	"log"
	"sync"
	"time"
	"math/big"
	"bytes"
	//"github.com/ethereum/go-ethereum/crypto"
	//"github.com/ethereum/go-ethereum/p2p"
	"../../blockchain_go"
	"../../p2p"
	"../../p2p/nat"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"gopkg.in/fatih/set.v0"
	"github.com/ethereum/go-ethereum/rlp"
	"encoding/gob"
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
type Message struct {
	Data string
}
//type Message string

// propEvent is a block propagation, waiting for its turn in the broadcast queue.
type propEvent struct {
	block *types.Block
	td    *big.Int
}

type peer struct {
	id string

	*p2p.Peer
	rw p2p.MsgReadWriter

	version  int         // Protocol version negotiated
	forkDrop *time.Timer // Timed connection dropper if forks aren't validated in time

	head common.Hash
	td   *big.Int
	lock sync.RWMutex

	knownTxs    *set.Set                  // Set of transaction hashes known to be known by this peer
	knownBlocks *set.Set                  // Set of block hashes known to be known by this peer
	queuedTxs   chan []*types.Transaction // Queue of transactions to broadcast to the peer
	queuedProps chan *propEvent           // Queue of blocks to broadcast to the peer
	queuedAnns  chan *types.Block         // Queue of blocks to announce to the peer
	term        chan struct{}             // Termination channel to stop the broadcaster
}

func newPeer(version int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return &peer{
		Peer:        p,
		rw:          rw,
		version:     version,
		id:          fmt.Sprintf("%x", p.ID().Bytes()[:8]),
		knownTxs:    set.New(),
		knownBlocks: set.New(),
		queuedTxs:   make(chan []*types.Transaction, maxQueuedTxs),
		queuedProps: make(chan *propEvent, maxQueuedProps),
		queuedAnns:  make(chan *types.Block, maxQueuedAnns),
		term:        make(chan struct{}),
	}
}

// statusData is the network packet for the status message.
type statusData struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}

type txsync struct {
	p   *peer
	txs []*types.Transaction
}

type ProtocolManager struct {
	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
}


func MyProtocol() p2p.Protocol {
	return p2p.Protocol{
		Name:    "MyProtocol",
		Version: 1,
		Length:  1,
		Run:     msgHandler,
	}
}

var manager *ProtocolManager
func main() {
	//nodekey, _ := crypto.GenerateKey()
	wallets, err := core.NewWallets("192.168.1.196:2000")
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet("1NWUWL17WtxzSMVWhGm8UD7Y45ikFUHZCx")
	nodekey := &wallet.PrivateKey

	manager = &ProtocolManager{
		newPeerCh:   make(chan *peer),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
	}

	fmt.Println("nodekey:", nodekey.PublicKey)
	config := p2p.Config{
		MaxPeers:   10,
		PrivateKey: nodekey,
		NoDiscovery:     false,
		Name:       "my node name",
		NAT:nat.Any(),
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
	var myMessage = Message{Data:"foo"}//Message("foo")

	//p := newPeer(int(1), peer, ws)
	go func() {
		//for {
			//errc1 := make(chan error, 2)
			//payload := gobEncode(&myMessage)
			error := p2p.Send(ws, StatusMsg, &myMessage)
			if(error!=nil){
				//log.Panic(error)
				fmt.Println("~~~~~p2p.Send:", error)
			}
		//}
	}()
	fmt.Println("protocol start:", "msgHandler")
	//go func() {
	for {
		var myMessage1 Message
			msg,err := ws.ReadMsg()
		if err != nil {
			fmt.Println("-----p.rw.ReadMsg:", err)
			return err
		}
		fmt.Println("-----------> ws.ReadMsg(:", msg.Payload)
		/**
		经过反复测试 回复的字节流中第一个字段干扰到解码
		还不知道为什么加了这个字段
		而且解码一次错误之后第二次解码正常了 什么原因也不清楚
		(已经知道是decode.go stream的Kind 函数消费掉）
		 */
		var bytem  []byte
		s := rlp.NewStream(msg.Payload, uint64(msg.Size))
		bytem,err = s.Bytes()
		//_,_ = msg.Payload.Read(bytem)
		fmt.Println("-----msg.Payload.Read(:", bytem,"--",err)
		//msg.Size = msg.Size-1
		err = msg.Decode(&myMessage1)
		if err != nil {
			fmt.Println("-----msg.Decode(&myMessage):", err,"-",msg.Size)
			// handle decode error
			continue
		}
		fmt.Println("--------->msg:", myMessage1)
	}
	peer.Disconnect(p2p.DiscRequested)
	//}()

	/*
	for {
		select {
		case manager.newPeerCh <- p:
			//return manager.handle(peer)
			errc := make(chan error, 2)
			go func() {
				errc <- p2p.Send(p.rw, StatusMsg, &statusData{
					ProtocolVersion: uint32(p.version),
					NetworkId:       1,
					TD:              big.NewInt(2),
					//CurrentBlock:    nil,
					//GenesisBlock:    nil,
				})

			}()
		case <-manager.quitSync:
			return p2p.DiscQuitting
		}

		msg, err := ws.ReadMsg()
		if err != nil {
			return err
		}

		err = msg.Decode(&myMessage)
		if err != nil {
			// handle decode error
			continue
		}

		switch myMessage.data {
		case "foo":
			err := p2p.SendItems(ws, messageId, "bar")
			if err != nil {
				return err
			}
		default:
			fmt.Println("----------->recv:", myMessage)
		}
	}*/

	return nil
}


func gobEncode(data interface{}) []byte {
	var buff bytes.Buffer

	enc := gob.NewEncoder(&buff)
	err := enc.Encode(data)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}