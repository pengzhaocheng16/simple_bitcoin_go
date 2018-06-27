package p2pprotocol

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"../dotray"
	"time"
	"io"
	//"github.com/ethereum/go-ethereum/p2p"
	"../p2p"
	"../p2p/discover"
	"../blockchain_go"
)

const protocol = "tcp"
const nodeVersion = 1
const commandLength = 12

var nodeAddress string
var miningAddress string
var KnownNodes = []string{"192.168.1.196:2000"}
var blocksInTransit = [][]byte{}
var mempool = make(map[string]core.Transaction)

var send = make(chan interface{}, 1)


type Node struct {
	AddrList []string
}

type addr struct {
	AddrList []string
}

type block struct {
	AddrFrom string
	Block    []byte
}

type getblocks struct {
	AddrFrom string
	LastHash string
}

type getdata struct {
	AddrFrom string
	Type     string
	ID       []byte
}

type inv struct {
	AddrFrom string
	Type     string
	Items    [][]byte
}

type tx struct {
	AddFrom     string
	Transaction []byte
}

type verzion struct {
	Version    int
	BestHeight int
	lastHash string
	AddrFrom   string
}

type Command struct {
	Command string
	Data []byte
}

func commandToBytes(command string) []byte {
	var bytes [commandLength]byte

	for i, c := range command {
		bytes[i] = byte(c)
	}

	return bytes[:]
}

func bytesToCommand(bytes []byte) string {
	var command []byte

	for _, b := range bytes {
		if b != 0x0 {
			command = append(command, b)
		}
	}

	return fmt.Sprintf("%s", command)
}

func extractCommand(request []byte) []byte {
	return request[:commandLength]
}

func requestBlocks() {
	//for _, node := range KnownNodes {
		//sendGetBlocks(node)
	//}
}

func sendAddr(address p2p.MsgWriter) {
	nodes := addr{KnownNodes}
	nodes.AddrList = append(nodes.AddrList, nodeAddress)
	payload := gobEncode(nodes)
	//request := append(commandToBytes("addr"), payload...)
	command := Command{
		Command:"addr",
		Data:payload,
	}

	sendDataC(address, command)
}

func sendBlock(addr p2p.MsgWriter, b *core.Block) {
	fmt.Printf("send Block %s \n", b)
	fmt.Printf("send Block hash %x \n", b.Hash)
	data := block{nodeAddress, b.Serialize()}

	fmt.Printf("send Block len %n \n", len(data.Block))
	payload := gobEncode(data)
	//request := append(commandToBytes("block"), payload...)
	command := Command{
		Command:"block",
		Data:payload,
	}

	sendDataC(addr, command)
}

func sendData(addr string, data []byte) {
	isbroadcast := 1
	command := bytesToCommand(data[:commandLength])
	fmt.Printf("send %s command to node %s from %s\n", command,addr,nodeAddress)

	switch command {
	case "addr":
		isbroadcast = 0
	case "block":
		isbroadcast = 0
	case "inv":
		isbroadcast = 0
	case "getblocks":
		isbroadcast = 0
	case "getdata":
		isbroadcast = 0
	case "tx":
		isbroadcast = 0
	case "version":
		isbroadcast = 0
	default:
		fmt.Println("Unknown command!")
	}

	if(isbroadcast == 1){
		go func() {
			send <- data
			fmt.Println("send message：", len(data))
		}()
	}else{
		conn, err := net.Dial(protocol, addr)
		now := time.Now().UnixNano()
		r := dotray.Request{
			ID:      now,
			Command: dotray.NormalRequest,
			Data:    data,
			From:    nodeAddress,
		}

		if err != nil {
			fmt.Printf("%s is not available\n", addr)
			var updatedNodes []string

			for _, node := range KnownNodes {
				if node != addr {
					updatedNodes = append(updatedNodes, node)
				}
			}

			KnownNodes = updatedNodes

			return
		}
		defer conn.Close()


		//也可以这样实现：
		//encoder := gob.NewEncoder(conn)
		//encoder.Encode(r)
		var rdata = gobEncode(r)
		var datas = ""
		gobDecode(data,datas)
		fmt.Println("send message：", datas)
		_, err = io.Copy(conn, bytes.NewReader(rdata))
		if err != nil {
			log.Panic(err)
		}
	}
}

func sendDataC(w p2p.MsgWriter, data Command) error{
	err := p2p.Send(w, StatusMsg, &data)
	return err
}

func sendInv(addr p2p.MsgWriter, kind string, items [][]byte) {
	inventory := inv{nodeAddress, kind, items}
	payload := gobEncode(inventory)
	//request := append(commandToBytes("inv"), payload...)

	command := Command{
		Command:"inv",
		Data:payload,
	}

	sendDataC(addr, command)
}

func sendGetBlocks(addr p2p.MsgWriter, lastHash string) {
	payload := gobEncode(getblocks{nodeAddress,lastHash})
	//request := append(commandToBytes("getblocks"), payload...)

	command := Command{
		Command:"getblocks",
		Data:payload,
	}

	sendDataC(addr, command)
}

func sendGetData(addr p2p.MsgWriter, kind string, id []byte) {
	payload := gobEncode(getdata{nodeAddress, kind, id})
	//request := append(commandToBytes("getdata"), payload...)

	command := Command{
		Command:"getdata",
		Data:payload,
	}

	sendDataC(addr, command)
}

func SendTx(addr p2p.MsgWriter, tnx *core.Transaction) {
	data := tx{nodeAddress, tnx.Serialize()}
	payload := gobEncode(data)
	//request := append(commandToBytes("tx"), payload...)

	command := Command{
		Command:"tx",
		Data:payload,
	}

	sendDataC(addr, command)
}

func SendVersion(addr p2p.MsgWriter, bc *core.Blockchain) {
	bestHeight,lastHash := bc.GetBestHeight()
	payload := gobEncode(verzion{nodeVersion, bestHeight,lastHash, nodeAddress})
	//request := append(commandToBytes("version"), payload...)

	command := Command{
		Command:"version",
		Data:payload,
	}

	sendDataC(addr, command)
}

func handleAddr(command Command) {
	var buff bytes.Buffer
	var payload addr

	buff.Write(command.Data)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	KnownNodes = append(KnownNodes, payload.AddrList...)
	fmt.Printf("There are %d known nodes now!\n", len(KnownNodes))
	requestBlocks()
}

/**
 1 validate every incoming block before adding it to the blockchain.
 2 Instead of running UTXOSet.Reindex(), UTXOSet.Update(block) should be used,
because if blockchain is big,it’ll take a lot of time to reindex the whole UTXO set.
 3 if transaction confirmation number less than 6 send 1 confirmation broadcast
 */
func handleBlock(p *Peer, command Command, bc *core.Blockchain) {
	var buff bytes.Buffer
	var payload block

	buff.Write(command.Data)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	blockData := payload.Block
	fmt.Printf("Recevied new Block len %n \n", len(blockData))
	block := core.DeserializeBlock(blockData)

	valid,reason := bc.IsBlockValid(block)
	if(valid){
		bc.AddBlock(block)
	}else{
		fmt.Printf("Block not Valid reason %d  %x\n",reason,block.Hash)
		return
	}
	fmt.Printf("Added block %x\n", block.Hash)

	fmt.Printf("len(blocksInTransit) %s\n",len(blocksInTransit))
	if len(blocksInTransit) > 0 {
		blockHash := blocksInTransit[len(blocksInTransit)-1]
		//sendGetData(payload.AddrFrom, "block", blockHash)
		sendGetData(p.Rw, "block", blockHash)
		if(len(blocksInTransit) > 1){
			blocksInTransit = blocksInTransit[:len(blocksInTransit)-1]
		}else{
			blocksInTransit = [][]byte{}
		}
	} else {
		//UTXOSet := UTXOSet{bc}
		//UTXOSet.Reindex()
	}
	UTXOSet := core.UTXOSet{bc}
	UTXOSet.Update(block)
}

func handleInv(p *Peer,command Command, bc *core.Blockchain) {
	var buff bytes.Buffer
	var payload inv

	buff.Write(command.Data)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Recevied inventory with %d %s\n", len(payload.Items), payload.Type)

	if payload.Type == "block" {
		blocksInTransit = payload.Items

		blockHash := payload.Items[len(blocksInTransit)-1]
		//sendGetData(payload.AddrFrom, "block", blockHash)
		sendGetData(p.Rw, "block", blockHash)
		fmt.Printf("==========>request payload.Items[0]-blockhash %x %s\n", blockHash, payload.Type)
		newInTransit := [][]byte{}
		for _, b := range blocksInTransit {
			if bytes.Compare(b, blockHash) != 0 {
				newInTransit = append(newInTransit, b)
			}
		}
		blocksInTransit = newInTransit
	}

	if payload.Type == "tx" {
		txID := payload.Items[0]

		if mempool[hex.EncodeToString(txID)].ID == nil {
			//sendGetData(payload.AddrFrom, "tx", txID)
			sendGetData(p.Rw, "tx", txID)
		}
	}
}

func handleGetBlocks(p *Peer,command Command, bc *core.Blockchain) {
	var buff bytes.Buffer
	var payload getblocks

	buff.Write(command.Data)
	gob.NewDecoder(&buff)
	//dec := gob.NewDecoder(&buff)
	//err := dec.Decode(&payload)
	err := gobDecode(buff.Bytes(),&payload)

	fmt.Printf("Recevied getblocks payload with %s\n", &payload)
	if err != nil {
		log.Panic(err)
	}

	blocks := bc.GetBlockHashes(payload.LastHash)
	if(len(blocks) != 0) {
		//sendInv(payload.AddrFrom, "block", blocks)
		sendInv(p.Rw, "block", blocks)
	}
}

func handleGetData(p *Peer,command Command, bc *core.Blockchain) {
	var buff bytes.Buffer
	var payload getdata

	buff.Write(command.Data)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	if payload.Type == "block" {
		block, err := bc.GetBlock([]byte(payload.ID))
		if err != nil {
			return
		}

		//sendBlock(payload.AddrFrom, &block)
		sendBlock(p.Rw, &block)
	}

	if payload.Type == "tx" {
		txID := hex.EncodeToString(payload.ID)
		tx := mempool[txID]

		//SendTx(payload.AddrFrom, &tx)
		SendTx(p.Rw, &tx)
		//TODO delete from queue after user new transaction been comfirmed
		// delete(queue, txID)
	}
}

func handleTx(p *Peer, command Command, bc *core.Blockchain) {
	var buff bytes.Buffer
	var payload tx

	buff.Write(command.Data)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	txData := payload.Transaction
	tx := core.DeserializeTransaction(txData)
	mempool[hex.EncodeToString(tx.ID)] = tx
	//TODO no miner node instead of KnownNodes[0]
	if nodeAddress == KnownNodes[0] {
		for _, node := range KnownNodes {
			if node != nodeAddress && node != payload.AddFrom {
				//sendInv(node, "tx", [][]byte{tx.ID})
				sendInv(p.Rw, "tx", [][]byte{tx.ID})
			}
		}
	} else {
		if len(mempool) >= 2 && len(miningAddress) > 0 {
		MineTransactions:
			var txs []*core.Transaction

			for id := range mempool {
				tx := mempool[id]
				if bc.VerifyTransaction(&tx) {
					txs = append(txs, &tx)
				}
			}

			if len(txs) == 0 {
				fmt.Println("All transactions are invalid! Waiting for new ones...")
				return
			}

			cbTx := core.NewCoinbaseTX(miningAddress, "")
			txs = append(txs, cbTx)

			newBlock := bc.MineBlock(txs)
			if(newBlock != nil){
				UTXOSet := core.UTXOSet{bc}
				//UTXOSet.Reindex()
				UTXOSet.Update(newBlock)
				fmt.Println("New block is mined!")

				for _, node := range KnownNodes {
					if node != nodeAddress {
						//sendInv(node, "block", [][]byte{newBlock.Hash})
						sendInv(p.Rw, "block", [][]byte{newBlock.Hash})
					}
				}
			}
			for _, tx := range txs {
				txID := hex.EncodeToString(tx.ID)
				delete(mempool, txID)
			}

			if len(mempool) > 0 {
				goto MineTransactions
			}
		}
	}
}

func handleVersion(p *Peer, command Command, bc *core.Blockchain) {
	var buff bytes.Buffer
	var payload verzion

	//buff.Write(request[commandLength:])
	buff.Write(command.Data)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	//fmt.Println("receive payload：", payload.BestHeight)
	myBestHeight,myLastHash := bc.GetBestHeight()
	foreignerBestHeight := payload.BestHeight

	if myBestHeight < foreignerBestHeight {
		//sendGetBlocks(payload.AddrFrom,myLastHash)
		sendGetBlocks(p.Rw,myLastHash)
	} else if myBestHeight > foreignerBestHeight {
		//sendVersion(payload.AddrFrom, bc)
		SendVersion(p.Rw, bc)
	}

	//sendAddr(payload.AddrFrom)
	if !nodeIsKnown(payload.AddrFrom) {
		KnownNodes = append(KnownNodes, payload.AddrFrom)
	}
}

//func handleConnection(conn net.Conn, bc *core.Blockchain) {
func HandleConnection(p *Peer,command Command, bc *core.Blockchain) {
	//request, err := ioutil.ReadAll(conn)
	//if err != nil {
	//	log.Panic(err)
	//}
	//command := bytesToCommand(request[:commandLength])
	fmt.Printf("Received %s command\n", command)

	switch command.Command {
	case "addr":
		handleAddr(command)
	case "block":
		handleBlock(p,command, bc)
	case "inv":
		handleInv(p,command, bc)
	case "getblocks":
		handleGetBlocks(p,command, bc)
	case "getdata":
		handleGetData(p,command, bc)
	case "tx":
		handleTx(p,command, bc)
	case "version":
		handleVersion(p,command, bc)
	default:
		fmt.Println("Unknown command!")
	}

	//conn.Close()
}


/*func handleConnectionR(requestR *dotray.Request, bc *core.Blockchain) {
	var data = requestR.Data.([]byte)
	var request = data

	fmt.Printf("There are %d known nodes now!\n", len(KnownNodes))
	command := bytesToCommand(request[:commandLength])
	fmt.Printf("Received %s command\n", command)

	switch command {
	case "addr":
		handleAddr(request)
	case "block":
		handleBlock(request, bc)
	case "inv":
		handleInv(request, bc)
	case "getblocks":
		handleGetBlocks(request, bc)
	case "getdata":
		handleGetData(request, bc)
	case "tx":
		handleTx(request, bc)
	case "version":
		handleVersion(request, bc)
	default:
		fmt.Println("Unknown command!")
	}

}*/

// StartServer starts a node
func StartServer(nodeID, minerAddress string) {
	//nodeAddress = fmt.Sprintf("localhost:%s", nodeID)
	nodeAddress = nodeID

	miningAddress = minerAddress

	/*
	ln, err := net.Listen(protocol, nodeAddress)
	if err != nil {
		log.Panic(err)
	}
	defer ln.Close()
	*/
/*
	recv := make(chan interface{}, 1)
	var laddr = nodeAddress
	var saddr = KnownNodes[0]

		// start the p2p node
		go func() {
			err := dotray.StartNode(laddr, saddr, send, recv)
			if err != nil {
				panic("node start panic:" + err.Error())
			}
		}()

		// wait 2 second for p2p node started
		time.Sleep(2 * time.Second)

		// query 10 nodes address from p2p network
		nodeIDs := dotray.QueryNodes(10)
		fmt.Println("query nodes:", nodeIDs)
	*/
	 wallets, err := core.NewWallets("192.168.1.196:2000")
	 if err != nil {
		 log.Panic(err)
	 }
	 walletaddrs := wallets.GetAddresses()
	 wallet := wallets.GetWallet(walletaddrs[0])
	 var peers []*discover.Node
	 if(nodeID!="192.168.1.196:2000"){
	 	peers = []*discover.Node{&discover.Node{IP: net.ParseIP("192.168.1.196"),TCP:2000,UDP:2000,ID: discover.PubkeyID(&wallet.PrivateKey.PublicKey)}}
	 }else{
	 	peers = nil
	 }
	 wallets1, err := core.NewWallets(nodeID)
	 if err != nil {
		 log.Panic(err)
	 }
	 //wallet1 := wallets1.GetWallet("1NWUWL17WtxzSMVWhGm8UD7Y45ikFUHZCx")
	walletaddrs1 := wallets1.GetAddresses()
	wallet1 := wallets1.GetWallet(walletaddrs1[0])
	 config := p2p.Config{
		 PrivateKey:      &wallet1.PrivateKey,
		 MaxPeers:        10,
		 NoDiscovery:     false,
		 Dialer:          nil,
		 EnableMsgEvents: true,
		 BootstrapNodes:peers,
		 Name:nodeID,
		 //NAT:nat.Any(),
		 ListenAddr:nodeAddress,
		 Protocols:  []p2p.Protocol{MyProtocol()},
	 }
	 running := &p2p.Server{
		 Config: config,
	 }
	 err = running.Start()
	 if err != nil {
		 panic("server start panic:" + err.Error())
	 }
 fmt.Println("NodeInfo:", running.NodeInfo())

	//bc := NewBlockchain(nodeID)

	//if nodeAddress != KnownNodes[0] {
	//	sendVersion(KnownNodes[0], bc)
	//}

	select {}
	/*
	// receive message from other nodes
	for {
		select {
		case r := <-recv:
			res := r.(*dotray.Request)
			if(res.From != nodeAddress){
				go handleConnectionR(res, bc)
				fmt.Printf("receive message: %v from other node: \"%s\" \n", len(res.Data.([]byte)), res.From)
			}
			//datar := gobEncode(res.Data)
			//dattas := string(datar)
		}
	}*/

	/*for {
		conn, err := ln.Accept()
		if err != nil {
			log.Panic(err)
		}
		go handleConnection(conn, bc)
	}*/
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

// Decode
// 用gob进行数据解码
//
func gobDecode(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}


func nodeIsKnown(addr string) bool {
	for _, node := range KnownNodes {
		if node == addr {
			return true
		}
	}

	return false
}

