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
	"os"
	."../boltqueue"
	"gopkg.in/fatih/set.v0"
	"os/signal"
	"syscall"
	"../node"
	//"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/crypto"

	"../blockchain_go/rawdb"
	"../p2p/nat"
	"../blockchain_go/state"
)

const protocol = "tcp"
const nodeVersion = 1
const commandLength = 12
// This is the target size for the packs of transactions sent by txsyncLoop.
// A pack can get larger than this if a single transactions exceeds this size.
const txsyncPackSize = 100 * 1024

var nodeAddress string
var miningAddress string
var BootNodes = []string{"119.27.191.247:2000"}
var BootPeers = []*discover.Node{}
var CurrentNodeInfo *p2p.NodeInfo
var blocksInTransit = [][]byte{}
var blocksInTransitSet = set.New(set.SetType(set.ThreadSafe))

var send = make(chan interface{}, 1)

var node_id string
var Manager *ProtocolManager

var (
	testNodeKey, _ = crypto.GenerateKey()
)

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
		log.Println("--start block valid op")
		events := bc.Events([]*core.Block{block})
		bc.PostChainEvents(events,nil)
		if(!p.knownBlocks.Has(hex.EncodeToString(block.Hash.Bytes()))){
			log.Println("--in block valid bf block added ")
			bc.AddBlock(block)

			log.Println("--in block valid af block added ")
			//confirm transaction from wallet
			//wallets1, err := core.NewWallets(bc.NodeId)
			//if err != nil {
			//	log.Panic(err)
			//}
			//walletaddrs1 := wallets1.GetAddresses()
			//for _,walletAddress := range walletaddrs1{
				confirmTx(block,bc.NodeId)
			//}
			log.Println("--end block valid af block confirmed ")

			p.lock.RLock()
			//defer p.lock.RUnlock()
			//Manager.CurrTd = block.Height
			p.knownBlocks.Add(hex.EncodeToString(block.Hash.Bytes()))
			p.lock.RUnlock()
		}

		time := time.Now()
		block.ReceivedAt = time

		/*pending := Manager.TxMempool
		//fmt.Println("---len(pending) ",len(pending))
		for _, tx := range pending {
			//fmt.Println("---syncTransactions ")
			if block.HasTransactions(tx.ID){
				delete(Manager.TxMempool, hex.EncodeToString(tx.ID))
			}
		}*/
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
			blocksInTransitSet.Remove(hex.EncodeToString(block.Hash.Bytes()))
		}
		if(len(blocksInTransit) > 1){
			blocksInTransit = blocksInTransit[:len(blocksInTransit)-1]
		}else{
			blocksInTransit = [][]byte{}
		}
	} else {
		//UTXOSet := UTXOSet{bc}
		//UTXOSet.Reindex()

		for _,peer := range Manager.Peers.Peers{
			SendVersion(peer.Rw, bc)
		}
	}
	UTXOSet := core.UTXOSet{bc}
	UTXOSet.Update(block)
	rawdb.WriteCanonicalHash(bc.Db, block.Hash, block.Height.Uint64())
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

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

//  broadcast block after txs mined
func handleTx(p *Peer, command Command, bc *core.Blockchain) error{
	var buff bytes.Buffer
	var payload tx

	buff.Write(command.Data)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	txData := payload.Transaction
	//TODO DeserializeTransaction return tx pointer
	tx := core.DeserializeTransaction(txData)
	if &tx == nil {
		return errResp(ErrDecode, "transaction %d is nil", 0)
	}

	//tx.SetSize(uint64(len(txData)))
	tx.Size()

	p.MarkTransaction(tx.ID)

	var pendingState = Manager.txPool.State()
	// Make sure the transaction is signed properly
	from, err := core.Sender(Manager.txPool.Signer, &tx)
	if err != nil {
		log.Fatal("error",core.ErrInvalidSender)
	}
	var nonce = pendingState.GetNonce(from)
	if nonce < tx.Nonce() {
		pendingState.SetNonce(from, tx.Nonce())
	}

	Manager.TxMempool[hex.EncodeToString(tx.ID)] = &tx
	txs := []*core.Transaction{&tx}
	Manager.txPool.AddRemotes(txs)

	/*var tnxs core.Transactions
	tnxs = append(tnxs, &tx)
	Manager.BroadcastTxs(tnxs)*/

	pending, err := Manager.txPool.Pending()
	if err != nil {
		log.Panic(err)
	}
	var txlist core.Transactions
	for _, batch := range pending {
		txlist = append(txlist, batch...)
	}

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
		//if len(Manager.TxMempool) >= 2 && len(miningAddress) > 0 {
		if len(txlist) >= 2 && len(miningAddress) > 0 {
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
			queueFile := state.GenWalletStateDbName(bc.NodeId)
			pqueue, errcq := NewPQueue(queueFile)
			if errcq != nil {
				log.Panic("create queue error",errcq)
			}
			defer pqueue.Close()
			var sizeTotal float64 = 0
			//for id,txMine := range Manager.TxMempool {
			for _,txMine := range txlist {
				//in case of double spend
				for _, vin := range txMine.Vin {
					pqueue.SetMsg(1, vin.Txid, txMine.ID)
				}
				//verify transaction
				//block txs size limit to 4M
				if(core.VerifyTx(*txMine,bc) && sizeTotal < 4 * 1024 *1024) {
					sizeTotal = sizeTotal + float64(txMine.Size())
					txs = append(txs, txMine)
				}
			}
			if len(txs)>1 && len(txs) < 2 && len(miningAddress) > 0 {
				for _, vin := range txs[0].Vin {
					pqueue.DeleteMsg(1, vin.Txid)
				}
				return errResp(1, "transactions not enough" )
			}

			if len(txs) == 0 {
				fmt.Println("All transactions are invalid! Waiting for new ones...")
				return errResp(2, "transactions empty" )
			}

			var pendingState = Manager.txPool.State()
			fmt.Println("==>NewCoinbaseTX ")
			//var nonce = pendingState.GetNonce(core.Base58ToCommonAddress([]byte(miningAddress)))

			var commonaddr = core.Base58ToCommonAddress([]byte(miningAddress))
			var nonce,_ = pendingState.StateDB.GetTransactionNonce(commonaddr.String())
			cbTx := core.NewCoinbaseTX(nonce+1,miningAddress, "",bc.NodeId)
			pendingState.StateDB.PutTransaction(cbTx.ID,cbTx.Serialize(),commonaddr.String())
			pendingState.SetNonce(commonaddr,nonce+1)

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
			}/*
			for _, tx := range txs {
				txID := hex.EncodeToString(tx.ID)
				delete(Manager.TxMempool, txID)
				//commit transaction nonce
				var pendingState = Manager.txPool.State()
				from, err := core.Sender(Manager.txPool.Signer, tx)
				if err != nil {
					log.Panic( core.ErrInvalidSender)
				}
				pendingState.SetNonce(from,tx.Data.AccountNonce)

				//statedb.Finalise(true)
			}*/

			fmt.Println("==>after mine len(txlist) ",len(txlist))
			//if len(Manager.TxMempool) > 0 {
			if len(txlist) > 0 {
				goto MineTransactions
			}
		}
	}
	return nil
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
	myLastHashStr := hex.EncodeToString(myLastHash.Bytes())
	foreignerBestHeight := payload.BestHeight

	p.Td = foreignerBestHeight

	if myBestHeight.Cmp(foreignerBestHeight) < 0 {
		//sendGetBlocks(payload.AddrFrom,myLastHash)
		if(myBestHeight.Cmp(foreignerBestHeight) < 0){
			enqueueVersion(myLastHash.Bytes())
			sendGetBlocks(p.Rw,myLastHashStr)
		}
		go func() {
			select {
			case Manager.BestTd <- foreignerBestHeight:
				fmt.Println("---Manager.BestTd:", &Manager.BestTd)
			}
		}()
	} else if myBestHeight.Cmp(foreignerBestHeight) >= 0 {
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
			log.Println("error:conflict ",err2)
			blockshash := bc.GetBlockHashesOf(10)
			data := statusData{
				uint32(1),
				CurrentNodeInfo.ID,
				myBestHeight,
				myLastHash,
				bc.GenesisHash,
				blockshash,//up to 10 blocks hash potential confilict block start at
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
	defer bc.Db.Close()
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
func StartServer(nodeID, minerAddress string, ipcPath string,host string,port int) {
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
	 wallets, err := core.NewWallets("119.27.191.247:2000")
	 if err != nil {
		 log.Panic(err)
	 }
	 walletaddrs := wallets.GetAddresses()
	 wallet := wallets.GetWallet(walletaddrs[0])
	 var peers []*discover.Node
	 if(nodeID!="119.27.191.247:2000"){
	 	peers = []*discover.Node{&discover.Node{IP: net.ParseIP("119.27.191.247"),TCP:2000,UDP:2000,ID: discover.PubkeyID(&wallet.PrivateKey.PublicKey)}}
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
		 NAT:nat.Any(),
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
	CurrentNodeInfo = running.NodeInfo()
 	fmt.Println("NodeInfo:", CurrentNodeInfo)

	if(ipcPath == ""){
		ipcPath = "cli\\test.ipc"
	}
	if(host == ""){
		host = node.DefaultHTTPHost
	}
	if(port == 0){
		port = node.DefaultHTTPPort
	}
	conf := &node.Config{
		Name: "test node",
		P2P:  config,
		Etherbase:common.BytesToAddress(wallet1.GetAddress()),
		NodeID:nodeID,
		IPCPath:ipcPath,
		HTTPHost:host,
		HTTPPort:port,
		HTTPCors:[]string{"*"},
		HTTPVirtualHosts:[]string{"localhost"},
		KeyStoreDir:"",
	}
	stack, err := node.New(conf)
	// Register a batch of life-cycle instrumented services
	services := map[string]node.InstrumentingWrapper{
		"A": node.InstrumentedServiceMakerA,
		"B": node.InstrumentedServiceMakerB,
		"C": node.InstrumentedServiceMakerC,
	}
	started := make(map[string]bool)
	stopped := make(map[string]bool)

	//fmt.Println("af NewBlockchain:")
	for id, maker := range services {
		id := id // Closure for the constructor
		constructor := func(*node.ServiceContext) (node.Service, error) {
			return &node.InstrumentedService{
				StartHook: func(*p2p.Server) { started[id] = true },
				StopHook:  func() { stopped[id] = true },
			}, nil
		}
		if err := stack.Register(maker(constructor)); err != nil {
			//t.Fatalf("service %s: registration failed: %v", id, err)
			log.Fatalf("service %s: registration failed: %v", id, err)
		}
	}
	// Restart the stack a few times and check successful service restarts
	//for i := 0; i < 2; i++ {
	//	if err := stack.Restart(nil); err != nil {
	//		log.Fatalf("iter %d: failed to restart stack: %v", i, err)
	//	}
	//}
	//if  len(started) != 3 {
	//	log.Fatalf("running/started mismatch: have %v/%d, want true/4", running, started)
	//}

	bc := core.NewBlockchain(nodeID)
	defer bc.Db.Close()

	//td,_:= bc.GetBestHeight()
	Manager = &ProtocolManager{
		nodeID:nodeID,
		Peers:       newPeerSet(),
		//Bc:bc,
		TxMempool:make(map[string]*core.Transaction),
		txsyncCh: make(chan *txsync),
		quitSync: make(chan struct{}),
		//BigestTd:td,
		BestTd: make(chan *big.Int),
	}

	err = stack.Register(func(ctx *node.ServiceContext) (node.Service, error) {
		fullNode, err := New(ctx,conf,bc)

		return fullNode, err
	})
	if err != nil {
		log.Fatalf("Failed to register the Ethereum service: %v", err)
	}
	StartNode(stack,running)


	//defer bc.Db.Close()
	// start sync handlers
	////go pm.syncer()
	go Manager.txsyncLoop()

	//if nodeAddress != BootNodes[0] {
	//	sendVersion(BootNodes[0], bc)
	//}

	select {}

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


func handleConflict(p *Peer, command Command, bc *core.Blockchain) {
	var buff bytes.Buffer
	var payload statusData

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
	//defer os.Remove(queueFile)

	// Dequeue history versiondata and sent version to the peer
	if size,err1 := versionPQueue.Size(1);err1 == nil && size >0 {
		var found common.Hash
		var hashs2del = make(map[string]common.Hash,1)
		var j = 0
	outer:for size,err1 := versionPQueue.Size(1);err1 == nil && size > 0 && j<10;{
			versionMsg, err2 := versionPQueue.Dequeue()
			if err2 != nil {
				log.Panic("create Version myLastHash queue error", err)
			}
			if(versionMsg == nil){
				break
			}
			myLastHash := versionMsg.Bytes()
			var hash common.Hash
			for _,hash = range payload.BlocksHash {
					//delete old conflict block
				blockHashs := bc.GetBlockHashesMap(myLastHash)
				for hashstr,blockhash := range blockHashs {
					found = blockhash
					if(hashstr != hash.String()){
						hashs2del[hashstr] = blockhash
					}else{
						break outer
					}
				}
			}
			j = j + 1
		}
		if(len(hashs2del) > 0 ){
			blockDeleted := bc.DelBlockHashes(hashs2del)
			if (len(blockDeleted) == 0) {
				log.Println("no blocks deleted !")
			}
		}
		SendVersionStartConflict(p.Rw, found.Bytes(), bc)
	}else {
		bestHeight, lastHash := bc.GetBestHeightLastHash()
		log.Printf("invalide block at height %d ", bestHeight)
		if err != nil {
			log.Panic(err)
		}
		var found common.Hash
		var hashs2del= make(map[string]common.Hash, 1)
		var hash0= common.Hash{}
		var j = 0
		outer1:for ; lastHash.String() != hash0.String() && j < 10; {
			var hash common.Hash
			for _,hash = range payload.BlocksHash {
				found = lastHash
				if hash.String() == lastHash.String() {
					break outer1
				}else{
					hashs2del[lastHash.String()] = lastHash
				}
			}
			var block, err1 = bc.GetBlock(lastHash.Bytes())
			if err1 != nil {
				log.Panic(err1)
			}
			lastHash = block.PrevBlockHash
			j = j + 1
		}
		blocksDeleted := bc.DelBlockHashes(hashs2del)
		if (len(blocksDeleted) == 0) {
			log.Println("no blocks deleted !")
		}
		SendVersionStartConflict(p.Rw, found.Bytes(), bc)
	}
}

func enqueueVersion(myLastHash []byte){
	//save every version command received in queue
	queueFile := fmt.Sprintf("version_%s.db", node_id)
	versionPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create Version myLastHash queue error",err)
	}

	defer versionPQueue.Close()
	//defer os.Remove(queueFile)
	eqerr := versionPQueue.Enqueue(1, NewMessageBytes(myLastHash))
	if err != nil {
		log.Panic("Version myLastHash Enqueue error",eqerr)
	}
}

//confirm transaction from wallet (not tranasaction from other node)
//TODO if there is blockchain conflict (blockchain fork) then the data is not valid need to delete all comfirmed uncomfirmed transactions
func confirmTx(newblock *core.Block,nodeID string) bool {
	//queueFile := fmt.Sprintf("%x_tx.db", wallet.GetAddress())
	queueFile := state.GenWalletStateDbName(nodeID)
	txPQueue, err := NewPQueue(queueFile)
	log.Println("-- af NewPQueue \n")
	if err != nil {
		log.Panic("create queue error", err)
	}
	defer txPQueue.Close()

	//defer os.Remove(queueFile)
	// priority 1 msg: spent utxo transaction id
	// priority 2 msg: comfirmation counter + tx block hash +  user's pending transaction id
	//loop block's txs if block's tx exist in queue then tx's confirmationCount +1
	//if confirmationCount == 6 remove priority 2 tx data:tx id and 1 tx data:tx's vin txid

	//transaction in first confirmed block
	for _, tx := range newblock.Transactions {
		var txid *Message
		var counter []byte
		txid = txPQueue.GetMsgBykey(2, tx.ID)

		if (txid != nil && txid.Bytes() != nil ) {
			counter = make([]byte,1)
			// counter  =  1
			counter[0] = 1
			// confirmation’s block hash 32 * 6 =192 bytes
			var blockHash = make([]byte,0)
			blockHash = append(blockHash[:], newblock.Hash.Bytes()...)
			fmt.Printf("  blockHash %d :\n", blockHash)
			var newiddata = make([]byte,0)
			newiddata = append(newiddata,counter...)
			newiddata = append(newiddata,blockHash...)
			var zero = make([]byte,160)
			newiddata = append(newiddata,zero...)
			fmt.Printf("  newiddata %d :\n", newiddata)

			fmt.Printf(" len newiddata %d :\n", len(newiddata))
			txPQueue.DeleteMsg(2, txid.Bytes())
			txPQueue.SetMsg(2, txid.Bytes(),newiddata )
		}
	}
	//transaction not in first confirmed block
	var counter []byte
	var iddata []byte
	var txidold []byte
	var bytelen int
	vall := txPQueue.GetAll(2)
	for txid, txiddata0 := range vall {
		fmt.Printf(" len newiddata0 %d :\n", txiddata0)
		if len(txiddata0.Bytes())<193{
			fmt.Printf(" len txid %x :\n", txid)
			continue
		}
		txiddata := txiddata0.Bytes()[1:192]

		hash1 := hex.EncodeToString(txiddata[:32])
		hash2 := hex.EncodeToString(txiddata[32:64])
		hash3 := hex.EncodeToString(txiddata[64:96])
		hash4 := hex.EncodeToString(txiddata[96:128])
		hash5 := hex.EncodeToString(txiddata[128:160])
		hash6 := hex.EncodeToString(txiddata[160:192])
		switch hex.EncodeToString(newblock.PrevBlockHash.Bytes()) {
		case hash1:
			bytelen = 32
			txidold = txiddata0.Key()
			break;
		case hash2:
			bytelen = 64
			txidold = txiddata0.Key()
			break;
		case hash3:
			bytelen = 96
			txidold = txiddata0.Key()
		case hash4:
			bytelen = 128
			txidold = txiddata0.Key()
		case hash5:
			bytelen = 160
			txidold = txiddata0.Key()
		case hash6:
			bytelen = 192
			txidold = txiddata0.Key()
			break
		}
		if (txidold != nil) {
			counter = txiddata0.Bytes()[:1]
			iddata = txiddata
		}
	}

	if (txidold!=nil) {
		// counter + 1 1 byte
		counter[0] = counter[0] + 1
		// confirmation’s block hash 32 * 6 =192 bytes
		var blockHash= make([]byte,(192-bytelen))
		blockHash = append(blockHash[:], newblock.Hash.Bytes()...)
		var newhash []byte
		for _, v := range blockHash {
			newhash = append(counter, v)
		}
		newhash = append(iddata[:bytelen],newhash ...)
		if (counter[0] == 6) {
			txPQueue.DeleteMsg(2, txidold)
			txMsg := txPQueue.GetMsgBykey(3,txidold)
			txSerialized := txMsg.Bytes()
			tx := core.DeserializeTransaction(txSerialized)
			for _,vin := range tx.Vin{
				txPQueue.DeleteMsg(1,vin.Txid)
			}
			//txPQueue.DeleteMsg(3,txidold)
		} else {
			txPQueue.SetMsg(2, txidold, newhash)
		}
	}
	return false
}


func StartNode(stack *node.Node,running *p2p.Server) {
	if err := stack.Start(running); err != nil {
		log.Fatalf("Error starting protocol stack: %v", err)
	}
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigc)
		<-sigc
		log.Println("Got interrupt, shutting down...")
		go stack.Stop()
		/*for i := 10; i > 0; i-- {
			<-sigc
			if i > 1 {
				log.Println("Already shutting down, interrupt more to panic.", "times", i-1)
			}
		}*/
		//debug.Exit() // ensure trace and CPU profile data is flushed.
		//debug.LoudPanic("boom")
	}()
}

