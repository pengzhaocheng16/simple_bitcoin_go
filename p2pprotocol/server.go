package p2pprotocol

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	//"../dotray"
	"time"
	//"github.com/ethereum/go-ethereum/p2p"
	"../p2p"
	"../p2p/discover"
	"../blockchain_go"
	"strings"
	"math/big"
	"github.com/ethereum/go-ethereum/common"
	"math/rand"
	"os"
	."../boltqueue"
	"gopkg.in/fatih/set.v0"
)

const protocol = "tcp"
const nodeVersion = 1
const commandLength = 12
// This is the target size for the packs of transactions sent by txsyncLoop.
// A pack can get larger than this if a single transactions exceeds this size.
const txsyncPackSize = 100 * 1024

var nodeAddress string
var miningAddress string
var BootNodes = []string{"192.168.1.196:2000"}
var BootPeers = []*discover.Node{}
var CurrentNodeInfo *p2p.NodeInfo
var blocksInTransit = [][]byte{}
var blocksInTransitSet = set.New()

var send = make(chan interface{}, 1)

var node_id string
var Manager *ProtocolManager

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
	BestHeight *big.Int
	LastHash string
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
	//for _, node := range BootNodes {
		//sendGetBlocks(node)
	//}
}

func sendAddr(address p2p.MsgWriter) {
	nodes := addr{BootNodes}
	nodes.AddrList = append(nodes.AddrList, nodeAddress)
	payload := gobEncode(nodes)
	//request := append(commandToBytes("addr"), payload...)
	command := Command{
		Command:"addr",
		Data:payload,
	}

	sendDataC(address, command)
}

func sendBlock(addr p2p.MsgWriter, b *core.Block) error{
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

	return sendDataC(addr, command)
}
/*
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

			for _, node := range BootNodes {
				if node != addr {
					updatedNodes = append(updatedNodes, node)
				}
			}

			BootNodes = updatedNodes

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
}*/

func sendDataC(w p2p.MsgWriter, data Command) error{
	err := p2p.Send(w, StatusMsg, &data)
	return err
}

func sendInv(addr p2p.MsgWriter, kind string, items [][]byte) error{
	inventory := inv{nodeAddress, kind, items}
	payload := gobEncode(inventory)
	//request := append(commandToBytes("inv"), payload...)

	command := Command{
		Command:"inv",
		Data:payload,
	}

	return sendDataC(addr, command)
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

func SendTx(p *Peer,addr p2p.MsgWriter, tnx *core.Transaction) {
	fmt.Printf("tnx.Size()  %s\n", tnx.Size())

	data := tx{nodeAddress, tnx.Serialize()}
	payload := gobEncode(data)
	//request := append(commandToBytes("tx"), payload...)

	p.MarkTransaction(tnx.ID)

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

	Manager.BigestTd = bestHeight

	command := Command{
		Command:"version",
		Data:payload,
	}
	log.Print("send version --",bestHeight)

	sendDataC(addr, command)
}

func SendVersionStartConflict(addr p2p.MsgWriter, historyLasthash []byte, bc *core.Blockchain) {
	historyLastblock,err := bc.GetBlock(historyLasthash)
	if err != nil {
		log.Panic("create queue error",err)
	}
	bestHeight := historyLastblock.Height
	lasthash := hex.EncodeToString(historyLasthash)
	version := verzion{nodeVersion, bestHeight,lasthash, nodeAddress}
	payload := gobEncode(version)
	//request := append(commandToBytes("version"), payload...)

	command := Command{
		Command:"version",
		Data:payload,
	}
	log.Print("send version --",bestHeight)

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

	BootNodes = append(BootNodes, payload.AddrList...)
	fmt.Printf("There are %d known nodes now!\n", len(BootNodes))
	requestBlocks()
}

/**
 1 validate every incoming block before adding it to the blockchain.
 2 Instead of running UTXOSet.Reindex(), UTXOSet.Update(block) should be used,
because if blockchain is big,it’ll take a lot of time to reindex the whole UTXO set.
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
	fmt.Println("Recevied new Block len %n \n", len(blockData))
	block := core.DeserializeBlock(blockData)
	fmt.Println("Recevied new Block hash %x \n", block.Hash)

	valid,reason := bc.IsBlockValid(block)
	if( valid ){
		if(!p.knownBlocks.Has(hex.EncodeToString(block.Hash))){
			bc.AddBlock(block)
			p.lock.RLock()
			//Manager.CurrTd = block.Height
			p.knownBlocks.Add(hex.EncodeToString(block.Hash))
			//defer p.lock.RUnlock()
			p.lock.RUnlock()
		}

		time := time.Now()
		block.ReceivedAt = time

		pending := Manager.TxMempool
		//fmt.Println("---len(pending) ",len(pending))
		for _, tx := range pending {
			//fmt.Println("---syncTransactions ")
			if(block.HasTransactions(tx.ID)){
				delete(Manager.TxMempool, hex.EncodeToString(tx.ID))
			}
		}
		//Manager.BroadcastBlock(block,true)
	}else{
		fmt.Printf("Block not Valid reason %d  %x\n",reason,block.Hash)
		return
	}
	fmt.Printf("Added block %x\n", block.Hash)

	fmt.Printf("len(blocksInTransit) %s\n",len(blocksInTransit))
	if len(blocksInTransit) > 0 {
		blockHash := blocksInTransit[len(blocksInTransit)-1]
		//sendGetData(payload.AddrFrom, "block", blockHash)
		blockHashStr := hex.EncodeToString(blockHash)
		if(blocksInTransitSet.Has(blockHashStr)){
			sendGetData(p.Rw, "block", blockHash)
			blocksInTransitSet.Remove(hex.EncodeToString(block.Hash))
		}
		if(len(blocksInTransit) > 1){
			blocksInTransit = blocksInTransit[:len(blocksInTransit)-1]
		}else{
			blocksInTransit = [][]byte{}
		}
	} else {
		//UTXOSet := UTXOSet{bc}
		//UTXOSet.Reindex()

		//after version command finished remove version command from queue
		/*queueFile := fmt.Sprintf("version_%s.db", node_id)
		versionPQueue, err := NewPQueue(queueFile)
		if err != nil {
			log.Panic("create queue error",err)
		}
		defer versionPQueue.Close()
		defer os.Remove(queueFile)

		size,_ := versionPQueue.Size(1)
		fmt.Printf("version queue size %d\n", size)
		if(size > 0){
			versionPQueue.Dequeue()
		}*/
		for _,peer := range Manager.Peers.Peers{
			SendVersion(peer.Rw, bc)
		}
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
		for _,item := range payload.Items {
			blocksInTransitSet.Add(hex.EncodeToString(item))
		}
		blockHash := payload.Items[len(blocksInTransit)-1]
		blockHashStr := hex.EncodeToString(blockHash)
		//sendGetData(payload.AddrFrom, "block", blockHash)

		if blocksInTransitSet.Has(blockHashStr) {
			sendGetData(p.Rw, "block", blockHash)
			blocksInTransitSet.Remove(blockHashStr)
		}
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
		var txID []byte
		for _,Item := range payload.Items{
			txID = Item
			if !p.knownTxs.Has(hex.EncodeToString(txID)) {
				//sendGetData(payload.AddrFrom, "tx", txID)
				sendGetData(p.Rw, "tx", txID)
			}
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

	if( p.forkDrop != nil){
		// Disable the fork drop timer
		p.forkDrop.Stop()
		p.forkDrop = nil
	}

	blocks := bc.GetBlockHashes(payload.LastHash)
	var blocksToS = [][]byte{}

	if(len(blocks) != 0) {
		for _, b := range blocks{
			hashStr := hex.EncodeToString(b)
			if(!p.knownBlocks.Has(hashStr)){
				p.knownBlocks.Add(hashStr)
				blocksToS = append(blocksToS,b)
			}
		}
		log.Println("==<len(blocksToS) %d",len(blocksToS))
		if(len(blocksToS)>0){
			sendInv(p.Rw, "block", blocksToS)
			//sendInv(payload.AddrFrom, "block", blocks)
		}
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
		tx := Manager.TxMempool[txID]

		if(tx!=nil){
			//SendTx(payload.AddrFrom, &tx)
			SendTx(p, p.Rw, tx)
			//TODO delete from queue after user new transaction been comfirmed
			// delete(queue, txID)
		}
	}
}

//  broadcast block after txs mined
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
	tx.SetSize(uint64(len(txData)))

	//tx.Size()

	Manager.TxMempool[hex.EncodeToString(tx.ID)] = &tx


	p.MarkTransaction(tx.ID)

	var tnxs core.Transactions
	tnxs = append(tnxs, &tx)
	Manager.BroadcastTxs(tnxs)

	if nodeAddress == BootNodes[0] {
		/*for _, node := range BootNodes {
			if node != nodeAddress && node != payload.AddFrom {
				//sendInv(node, "tx", [][]byte{tx.ID})
				sendInv(p.Rw, "tx", [][]byte{tx.ID})
			}
		}*/
		//sendInv(p.Rw, "tx", [][]byte{tx.ID})
	} else {
		fmt.Println("==>len tx")
		if len(Manager.TxMempool) >= 2 && len(miningAddress) > 0 {
		MineTransactions:
			var txs []*core.Transaction

			fmt.Println("==>Loopsync")
			//wait block sync complete
			select{
			case ch := <- Manager.BestTd:
				td,_ := bc.GetBestHeight()
				log.Println("---td 1:",td)
				if(td.Cmp(ch) == 0){
					log.Println("---td:",ch)
					break
				}
			}

			fmt.Println("==>VerifyTx ")
			for id := range Manager.TxMempool {
				//verify transaction
				if(core.VerifyTx(tx,bc)) {
					txs = append(txs, Manager.TxMempool[id])
				}
			}
			if len(txs) < 2 && len(miningAddress) > 0 {
				return
			}

			if len(txs) == 0 {
				fmt.Println("All transactions are invalid! Waiting for new ones...")
				return
			}

			fmt.Println("==>NewCoinbaseTX ")
			cbTx := core.NewCoinbaseTX(miningAddress, "")
			txs = append(txs, cbTx)

			newBlock := bc.MineBlock(txs)
			if(newBlock != nil){
				UTXOSet := core.UTXOSet{bc}
				//UTXOSet.Reindex()
				UTXOSet.Update(newBlock)
				fmt.Println("New block is mined!")

				for _, node := range BootNodes {
					if node != nodeAddress {
						//sendInv(node, "block", [][]byte{newBlock.Hash})
						//sendInv(p.Rw, "block", [][]byte{newBlock.Hash})
						//Manager.BroadcastBlock(newBlock,true)
						for _,peer := range Manager.Peers.Peers {
							SendVersion(peer.Rw,bc)
						}
					}
				}
			}
			for _, tx := range txs {
				txID := hex.EncodeToString(tx.ID)
				delete(Manager.TxMempool, txID)
			}

			fmt.Println("==>after mine len(Manager.TxMempool) ",len(Manager.TxMempool))
			if len(Manager.TxMempool) > 0 {
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

	log.Println("==>handle version receive payload BestHeight：", payload.BestHeight)
	myBestHeight,myLastHash := bc.GetBestHeightLastHash()
	myLastHashStr := hex.EncodeToString(myLastHash)
	foreignerBestHeight := payload.BestHeight

	p.Td = foreignerBestHeight

	if myBestHeight.Cmp(foreignerBestHeight) <= 0 {
		//sendGetBlocks(payload.AddrFrom,myLastHash)
		if(myBestHeight.Cmp(foreignerBestHeight) < 0){
			enqueueVersion(myLastHash)
			sendGetBlocks(p.Rw,myLastHashStr)
		}
		go func() {
			select {
			case Manager.BestTd <- foreignerBestHeight:
				fmt.Println("---Manager.BestTd:", &Manager.BestTd)
			}
		}()
	} else if myBestHeight.Cmp(foreignerBestHeight) > 0 {
		//sendVersion(payload.AddrFrom, bc)
		//SendVersion(p.Rw, bc)

		//check possible conflict fork
		//if there is conflict send  conflict msg to the node and ignore this node
		peerLastHash,err1 := hex.DecodeString(payload.LastHash)
		if err1 != nil {
			log.Panic(err1)
		}
		_,err2 := bc.GetBlock(peerLastHash)
		if(err2 != nil){
			log.Panic(err2)
			data := statusData{
				uint32(1),
				CurrentNodeInfo.ID,
				myBestHeight,
				myLastHash,
				bc.GenesisHash,
			}
			payload := gobEncode(data)
			p2p.Send(p.Rw, StatusMsg, &Command{"conflict",payload})
			return
		}
		go func(){
		select {
		case Manager.BestTd <- myBestHeight:
			fmt.Println("---Manager.BestTd:", &Manager.BestTd)
		}
		}()
	}

	if( p.forkDrop != nil){
		// Disable the fork drop timer
		p.forkDrop.Stop()
		p.forkDrop = nil
	}

	//sendAddr(payload.AddrFrom)
	//if !nodeIsKnown(payload.AddrFrom) {
	//	BootNodes = append(BootNodes, payload.AddrFrom)
	//}

}

//func handleConnection(conn net.Conn, bc *core.Blockchain) {
func HandleConnection(p *Peer,command Command, bc *core.Blockchain) {
	//request, err := ioutil.ReadAll(conn)
	//if err != nil {
	//	log.Panic(err)
	//}
	//command := bytesToCommand(request[:commandLength])
	fmt.Printf("Received %s command\n", command.Command)

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
	case "conflict":
		handleConflict(p,command, bc)
	default:
		fmt.Println("Unknown command!")
	}

	//conn.Close()
}


/*func handleConnectionR(requestR *dotray.Request, bc *core.Blockchain) {
	var data = requestR.Data.([]byte)
	var request = data

	fmt.Printf("There are %d known nodes now!\n", len(BootNodes))
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
	srp := strings.NewReplacer(":", "_")
	node_id = srp.Replace(nodeID)
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
	var saddr = BootNodes[0]

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
	 BootPeers = peers
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

	 /*
	//if there are some exception quit during syncing block then remove version command from queue at the start
	queueFile := fmt.Sprintf("version_%s.db", node_id)
	versionPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create queue error",err)
	}
	defer versionPQueue.Close()
	defer os.Remove(queueFile)

	size,_ := versionPQueue.Size(1)
	fmt.Printf("version queue size %d\n", size)
	if(size > 0){
		versionPQueue.Dequeue()
	}*/

	err = running.Start()
	if err != nil {
		 panic("server start panic:" + err.Error())
	}
	CurrentNodeInfo = running.NodeInfo()
 	fmt.Println("NodeInfo:", CurrentNodeInfo)


	//bc := core.NewBlockchain(nodeID)
	//fmt.Println("af NewBlockchain:")
	//td,_:= bc.GetBestHeight()
	//bc.Db.Close()
	Manager = &ProtocolManager{
		Peers:       newPeerSet(),
		//Bc:bc,
		TxMempool:make(map[string]*core.Transaction),
		txsyncCh: make(chan *txsync),
		quitSync: make(chan struct{}),
		//BigestTd:td,
		BestTd: make(chan *big.Int),
	}
	//defer bc.Db.Close()
	// start sync handlers
	////go pm.syncer()
	go Manager.txsyncLoop()

	//if nodeAddress != BootNodes[0] {
	//	sendVersion(BootNodes[0], bc)
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
	for _, node := range BootNodes {
		if node == addr {
			return true
		}
	}

	return false
}


// BroadcastTxs will propagate a batch of transactions to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTxs(txs core.Transactions) {
	var txset = make(map[*Peer]core.Transactions)

	// Broadcast transactions to a batch of peers not knowing about it
	for _, tx := range txs {
		peers := pm.Peers.PeersWithoutTx(tx.ID)
		log.Println("---len(PeersWithoutTx)   ",len(peers))
		for _, peer := range peers {
			txset[peer] = append(txset[peer], tx)
		}
		//log.Trace("Broadcast transaction", "hash", tx.Hash(), "recipients", len(peers))
	}
	// FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for peer, txs := range txset {
		peer.AsyncSendTransactions(txs)
	}
}

/*
// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *core.Block, propagate bool) {
	hash := block.Hash
	peers := pm.Peers.PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent,err := pm.blockchain.GetBlock(block.PrevBlockHash); &parent != nil &&err == nil {
			//td = new(big.Int).Add(block.Difficulty, pm.blockchain.GetTd(block.PrevBlockHash))
			td = block.Height
		} else {
			log.Println("Propagating dangling block", "number", block.Height, "hash", hash)
			return
		}
		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range transfer {
			peer.AsyncSendNewBlock(block, td)
		}
		log.Println("Propagated block", "hash", hash, "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// Otherwise if the block is indeed in out own chain, announce it
	//if pm.blockchain.HasBlock(hash, block.NumberU64()) {
	//	for _, peer := range peers {
	//		peer.AsyncSendNewBlockHash(block)
	//	}
	//	log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	//}
}*/


// syncTransactions starts sending all currently pending transactions to the given peer.
func (pm *ProtocolManager) syncTransactions(p *Peer) {
	var txs core.Transactions

	pending := pm.TxMempool
	//fmt.Println("---len(pending) ",len(pending))
	for _, batch := range pending {
		//fmt.Println("---syncTransactions ")
		txs = append(txs, batch)
	}
	if len(txs) == 0 {
		return
	}
	select {
	case pm.txsyncCh <- &txsync{p, txs}:
	case <-pm.quitSync:
	}
}


// txsyncLoop takes care of the initial transaction sync for each new
// connection. When a new peer appears, we relay all currently pending
// transactions. In order to minimise egress bandwidth usage, we send
// the transactions in small packs to one peer at a time.
func (pm *ProtocolManager) txsyncLoop() {
	var (
		pending = make(map[discover.NodeID]*txsync)
		sending = false               // whether a send is active
		pack    = new(txsync)         // the pack that is being sent
		done    = make(chan error, 1) // result of the send
	)

	// send starts a sending a pack of transactions from the sync.
	send := func(s *txsync) {
		// Fill pack with transactions up to the target size.
		size := common.StorageSize(0)
		pack.p = s.p
		pack.txs = pack.txs[:0]
		for i := 0; i < len(s.txs) && size < txsyncPackSize; i++ {
			pack.txs = append(pack.txs, s.txs[i])
			size += s.txs[i].Size()
		}
		// Remove the transactions that will be sent.
		s.txs = s.txs[:copy(s.txs, s.txs[len(pack.txs):])]
		if len(s.txs) == 0 {
			delete(pending, s.p.ID())
		}
		// Send the pack in the background.
		fmt.Println("---txsyncLoop len(pack.txs) ",len(pack.txs),"--",size)
		s.p.Log().Trace("Sending batch of transactions", "count", len(pack.txs), "bytes", size)
		sending = true
		go func() { done <- pack.p.SendTransactions(pack.txs) }()
	}

	// pick chooses the next pending sync.
	pick := func() *txsync {
		if len(pending) == 0 {
			return nil
		}
		n := rand.Intn(len(pending)) + 1
		for _, s := range pending {
			if n--; n == 0 {
				return s
			}
		}
		return nil
	}

	for {
		select {
		case s := <-pm.txsyncCh:
			fmt.Println("---txsyncLoop ")
			pending[s.p.ID()] = s
			if !sending {
				send(s)
			}
		case err := <-done:
			sending = false
			// Stop tracking peers that cause send failures.
			if err != nil {
				pack.p.Log().Debug("Transaction send failed", "err", err)
				delete(pending, pack.p.ID())
			}
			// Schedule the next send.
			if s := pick(); s != nil {
				send(s)
			}
		case <-pm.quitSync:
			return
		}
	}
}


func handleConflict(p *Peer, command Command, bc *core.Blockchain) {
	var buff bytes.Buffer
	var payload verzion

	//buff.Write(request[commandLength:])
	buff.Write(command.Data)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	//save every version command received in queue
	queueFile := fmt.Sprintf("version_%s.db", node_id)
	versionPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create Version Command queue error",err)
	}

	defer versionPQueue.Close()
	defer os.Remove(queueFile)

	// Dequeue history versiondata and sent version to the peer
	//for size,err1 := versionPQueue.Size(1);err1 == nil && size > 0;{
		versionMsg,err2:= versionPQueue.Dequeue()
		if err2 != nil {
			log.Panic("create Version myLastHash queue error",err)
		}
		myLastHash := versionMsg.Bytes()
		//delete old conflict block
		blockHashs := bc.GetBlockHashesMap(myLastHash)
		blockHashs1 := bc.DelBlockHashes(blockHashs)
		if(len(blockHashs1) == 0){
			log.Panic("no blocks deleted !")
		}
		SendVersionStartConflict(p.Rw,myLastHash,bc)
	//}

}

func enqueueVersion(myLastHash []byte){
	//save every version command received in queue
	queueFile := fmt.Sprintf("version_%s.db", node_id)
	versionPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create Version myLastHash queue error",err)
	}

	defer versionPQueue.Close()
	defer os.Remove(queueFile)
	eqerr := versionPQueue.Enqueue(1, NewMessageBytes(myLastHash))
	if err != nil {
		log.Panic("Version myLastHash Enqueue error",eqerr)
	}
}

func confirmTx(newblock core.Block,wallet core.Wallet) bool {
	queueFile := fmt.Sprintf("%x_tx.db", wallet.GetAddress())
	txPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create queue error", err)
	}
	defer txPQueue.Close()
	defer os.Remove(queueFile)
	// priority 1 msg: spent utxo transaction id
	// priority 2 msg: comfirmation counter + tx block hash +  user's pending transaction id
	//loop block's txs if block's tx exist in queue then tx's confirmationCount +1
	//if confirmationCount == 6 remove priority 2 tx data:tx id and 1 tx data:tx's vin txid
	var txid *Message
	var counter []byte
	var iddata []byte
	for _, tx := range newblock.Transactions {
		txid = txPQueue.GetMsg(2, tx.ID, 193)

		if (txid != nil) {
			counter = txid.Bytes()[:1]
			iddata = txid.Bytes()[1:]
		}
	}
	var txidold []byte
	vall := txPQueue.GetAll(2)
	for _, txiddata0 := range vall {
		txiddata := txiddata0[1:193]

		hash1 := hex.EncodeToString(txiddata[:32])
		hash2 := hex.EncodeToString(txiddata[32:64])
		hash3 := hex.EncodeToString(txiddata[64:96])
		hash4 := hex.EncodeToString(txiddata[96:128])
		hash5 := hex.EncodeToString(txiddata[128:160])
		hash6 := hex.EncodeToString(txiddata[160:192])
		switch hex.EncodeToString(newblock.PrevBlockHash) {
		case hash1:
		case hash2:
		case hash3:
		case hash4:
		case hash5:
		case hash6:
			txidold = txiddata0[193:]
			break

		}
		if (txidold != nil) {
			counter = txiddata0[:1]
			iddata = txidold
		}
	}

	if (txid != nil||txidold!=nil) {
		// counter + 1 1 byte
		counter[0] = counter[0] + 1
		// confirmation’s block hash 32 * 6 =192 bytes
		var blockHash= []byte{}
		blockHash = append(blockHash, newblock.Hash...)

		newtxid := append(counter, blockHash...)
		newtxid = append(counter, iddata...)
		if (counter[0] == 6) {
			txPQueue.DeleteMsg(2, newtxid, 193)
		} else {
			txPQueue.SetMsg(2, newtxid, 193)
		}
	}
	return false
}
