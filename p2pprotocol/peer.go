package p2pprotocol

import (
	"fmt"
	"sync"
	"time"
	"math/big"
	"errors"
	"log"
	//"github.com/ethereum/go-ethereum/crypto"
	//"github.com/ethereum/go-ethereum/p2p"
	//"github.com/ethereum/go-ethereum/log"
	"../blockchain_go"
	"../p2p"
	"../p2p/nat"
	"gopkg.in/fatih/set.v0"
	"os"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"math/rand"
	"../p2p/discover"
	"github.com/ethereum/go-ethereum/event"
	"math"
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
	TxMsg              = 0x02

	maxKnownTxs    = 32768 // Maximum transactions hashes to keep in the known list (prevent DOS)
	maxKnownBlocks = 1024  // Maximum block hashes to keep in the known list (prevent DOS)
)
const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096
)

var (
	errClosed            = errors.New("peer set is closed")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
)
//type Message string
var (
	daoChallengeTimeout = 6 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

// propEvent is a block propagation, waiting for its turn in the broadcast queue.
type propEvent struct {
	block *core.Block
	td    *big.Int
}

//Peer wrap p2p peer
type Peer struct {
	id string

	*p2p.Peer
	Rw p2p.MsgReadWriter

	version  int         // Protocol version negotiated
	forkDrop *time.Timer // Timed connection dropper if forks aren't validated in time

	head []byte
	Td   *big.Int
	lock sync.RWMutex

	knownTxs    *set.Set                  // Set of transaction hashes known to be known by this peer
	knownBlocks *set.Set                  // Set of block hashes known to be known by this peer
	queuedTxs   chan []*core.Transaction // Queue of transactions to broadcast to the peer
	queuedProps chan *propEvent           // Queue of blocks to broadcast to the peer
	//queuedAnns  chan *types.Block         // Queue of blocks to announce to the peer
	term        chan struct{}             // Termination channel to stop the broadcaster
}

func newPeer(version int, p *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	return &Peer{
		Peer:        p,
		Rw:          rw,
		version:     version,
		id:          fmt.Sprintf("%x", p.ID().Bytes()[:8]),
		knownTxs:    set.New(set.SetType(set.ThreadSafe)).(*set.Set),
		knownBlocks: set.New(set.SetType(set.ThreadSafe)).(*set.Set),
		queuedTxs:   make(chan []*core.Transaction, maxQueuedTxs),
		queuedProps: make(chan *propEvent, maxQueuedProps),
		//queuedAnns:  make(chan *types.Block, maxQueuedAnns),
		term:        make(chan struct{}),
	}
}

// peerSet represents the collection of active peers currently participating in
// the Ethereum sub-protocol.
type peerSet struct {
	Peers  map[string]*Peer
	lock   sync.RWMutex
	closed bool
}

// statusData is the network packet for the status message.
type statusData struct {
	ProtocolVersion uint32
	NetworkId       string
	TD              *big.Int
	CurrentBlockHash    common.Hash
	CurrentBlock 	*core.Block
	GenesisBlock    common.Hash
	BlocksHash      []common.Hash
}

type txsync struct {
	p   *Peer
	txs []*core.Transaction
}

type ProtocolManager struct {
	//networkId uint64
	nodeID string

	TxMempool map[string]*core.Transaction
	txPool *core.TxPool//*txPool
	maxPeers    int
	Bc *core.Blockchain

	// channels for fetcher, syncer, txsyncLoop
	//newPeerCh   chan *Peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	Peers      *peerSet

	eventMux      *event.TypeMux
	txsCh         chan core.NewTxsEvent
	txsSub        event.Subscription

	BigestTd *big.Int
	BestTd chan *big.Int

	Mu           sync.RWMutex
	//CurrTd *big.Int

	// wait group is used for graceful shutdowns during downloading
	// and processing
	//wg sync.WaitGroup
}

func (pm *ProtocolManager) removePeer(id string,blockchain *core.Blockchain) {
	// Short circuit if the peer was already removed
	peer := pm.Peers.Peer(id)
	if peer == nil {
		return
	}
	log.Print("+++Removing swarmchain peer", "peer", id)

	// Unregister the peer from the downloader and Ethereum peer set
	// pm.downloader.UnregisterPeer(id)
	if err := pm.Peers.Unregister(id); err != nil {
		log.Panic("Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}

	blockchain.Db.Close()
}


// BroadcastTxs will propagate a batch of transactions to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTxs(txs core.Transactions) {
	//pm.txPool.Lock()
	//defer pm.txPool.Unlock()//because pool is using blockchain database
	var txset = make(map[*Peer]core.Transactions)

	// Broadcast transactions to a batch of peers not knowing about it
	for _, tx := range txs {
		peers := pm.Peers.PeersWithoutTx(tx.ID)
		log.Println("---len(PeersWithoutTx)   ",len(peers))
		for _, peer := range peers {
			txset[peer] = append(txset[peer], tx)
		}
		log.Println("Broadcast transaction", "hash", tx.Hash(), "recipients", len(peers))
	}
	// FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for peer, txs := range txset {
		peer.AsyncSendTransactions(txs)
	}
	//mine
	bc := core.NewBlockchain(pm.nodeID)
	defer bc.Db.Close()
	mineBlock(bc)
}


// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *core.Block, propagate bool) {
	hash := block.Hash
	peers := pm.Peers.PeersWithoutBlock(hash.Bytes())

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent,err := pm.Bc.GetBlock(block.PrevBlockHash.Bytes()); &parent != nil &&err == nil {
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
}


// syncTransactions starts sending all currently pending transactions to the given peer.
func (pm *ProtocolManager) syncTransactions(p *Peer) {
	var txs core.Transactions

	pending, _ := pm.txPool.Pending()
	//fmt.Println("---len(pending) ",len(pending))
	for _, batch := range pending {
		//fmt.Println("---syncTransactions ")
		txs = append(txs, batch...)
		//txs = append(txs, batch)
	}
	pending1 := pm.TxMempool
	for _, batch := range pending1 {
		//fmt.Println("---syncTransactions ")
		txs = append(txs, batch)
		//txs = append(txs, batch)
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

func (pm *ProtocolManager) txBroadcastLoop() {
	for {
		select {
		case event := <-pm.txsCh:
			log.Println("---txBroadcastLoop :")
			pm.BroadcastTxs(event.Txs)
			// Err() channel will be closed when unsubscribing.
		case <-pm.txsSub.Err():
			return
		}
	}
}
/*
// Mined broadcast loop
func (pm *ProtocolManager) minedBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range pm.minedBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case core.NewMinedBlockEvent:
			pm.BroadcastBlock(ev.Block, true)  // First propagate block to peers
			pm.BroadcastBlock(ev.Block, false) // Only then announce to the rest
		}
	}
}*/

func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers
	pm.txsCh = make(chan core.NewTxsEvent, txChanSize)
	pm.txsSub = pm.txPool.SubscribeNewTxsEvent(pm.txsCh)
	go pm.txBroadcastLoop()
	pm.txPool.InitPool()

	// broadcast mined blocks
	/*pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})
		go pm.minedBroadcastLoop()*/
	/*
			// start sync handlers
			go pm.syncer()
			go pm.txsyncLoop()*/
}

func (pm *ProtocolManager) Stop() {
	log.Println("Stopping Ethereum protocol")

	pm.txsSub.Unsubscribe()        // quits txBroadcastLoop
	//pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	//pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.Peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	//pm.wg.Wait()

	log.Println("Ethereum protocol stopped")
}

func MyProtocol() p2p.Protocol {
	return p2p.Protocol{
		Name:    "MyProtocol",
		Version: 1,
		Length:  1,
		Run:     msgHandler,
	}
}


//var Peers = make(map[string]*Peer)
func main() {
	//nodekey, _ := crypto.GenerateKey()
	wallets, err := core.NewWallets("192.168.1.196:2000")
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet("1NWUWL17WtxzSMVWhGm8UD7Y45ikFUHZCx")
	nodekey := &wallet.PrivateKey

	Manager = &ProtocolManager{
		//newPeerCh:   make(chan *Peer),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
		Peers:       newPeerSet(),
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
	// Ignore maxPeers if this is a trusted peer
	//TODO: move to manager.handle(peer)
	if Manager.Peers.Len() >= Manager.maxPeers && !peer.Info().Network.Trusted {
		return p2p.DiscTooManyPeers
	}

	// Ignore maxPeers if this is a trusted peer
	fmt.Println("---protocol start:")
	p := newPeer(int(1), peer, ws)
	//Peers[p.id] = p

	fmt.Println("--- bf NewBlockchain:")
	//nodeID := os.Getenv("NODE_ID")
	nodeID := Manager.nodeID
	bc := core.NewBlockchain(nodeID)

	fmt.Println("--- bf Peers.Register:")
	// Register the peer locally
	if err := Manager.Peers.Register(p); err != nil {
		p.Log().Error("peer registration failed", "err", err)
		return err
	}
	defer Manager.removePeer(p.id,bc)


	fmt.Println("---syncTransactions:")
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	Manager.syncTransactions(p)

	// Start a timer to disconnect if the peer doesn't reply in time
	p.forkDrop = time.AfterFunc(daoChallengeTimeout, func() {
		fmt.Println("---Timed out DAO fork-check, dropping:")
		p.Log().Info("Timed out DAO fork-check, dropping")
		Manager.removePeer(p.id,bc)
	})

	//select {
		//case manager.newPeerCh <- p:
			//return manager.handle(peer)
			//SendVersion(p.Rw,bc)
		//case <-manager.quitSync:
			//return p2p.DiscQuitting
	//}
	log.Print(" --send version")

	SendVersion(p.Rw, bc)
	bc.Db.Close()

	// Make sure it's cleaned up if the peer dies off
	defer func() {
		if p.forkDrop != nil {
			p.forkDrop.Stop()
			p.forkDrop = nil
		}
	}()

	var myMessage Command
	for {
		msg, err := ws.ReadMsg()
		if err != nil {
			return err
		}
		//s := rlp.NewStream(msg.Payload, uint64(msg.Size))
		//_,err = s.Bytes()
		//fmt.Println("--------->s.Bytes() err:", err)

		err = msg.Decode(&myMessage)
		if err != nil {
			fmt.Println("--------->msg err:", err)
			// handle decode error
			continue
		}
		//bc1 := core.NewBlockchain(nodeID)

		HandleConnection(p,myMessage,nil)
		//bc1.Db.Close()
	}

	return nil
}

// newPeerSet creates a new peer set to track the active participants.
func newPeerSet() *peerSet {
	return &peerSet{
		Peers: make(map[string]*Peer),
	}
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known. If a new peer it registered, its broadcast loop is also
// started.
func (ps *peerSet) Register(p *Peer) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	//fmt.Println("--------->bf ps.closed:", p.id)
	if ps.closed {
		return errClosed
	}
	//fmt.Println("--------->bf errAlreadyRegistered:", p.id)
	if _, ok := ps.Peers[p.id]; ok {
		return errAlreadyRegistered
	}
	ps.Peers[p.id] = p
	fmt.Println("--------->peer Register:", p.id)
	fmt.Println("--------->ps.Peers:", ps.Peers)
	//load peer knowntx from db
	/*queueFile := fmt.Sprintf("version_%s.db", node_id)
	versionPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create knowntx queue error",err)
	}
	defer versionPQueue.Close()
	defer os.Remove(queueFile)
	var peerKnownTxs = make(map [string]*set.Set )
	peerKnownTxs[p.id] = p.knownTxs
	var kntxs  []byte
	kntxs = gobEncode(peerKnownTxs)
	errv := versionPQueue.Enqueue(2, NewMessageBytes(kntxs))
	if(errv != nil){
		log.Panic(errv)
	}*/

	go p.broadcast()

	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (ps *peerSet) Unregister(id string) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	fmt.Println("---------> Unregister ps.Peers:", ps.Peers)
	p, ok := ps.Peers[id]
	//_, ok := ps.Peers[id]
	if !ok {
		return errNotRegistered
	}
	//save peer knowntx to db
	/*queueFile := fmt.Sprintf("version_%s.db", node_id)
	versionPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create knowntx queue error",err)
	}
	defer versionPQueue.Close()
	defer os.Remove(queueFile)
	var peerKnownTxs = make(map [string]*set.Set )
	peerKnownTxs[p.id] = p.knownTxs
	var kntxs  []byte
	kntxs = gobEncode(peerKnownTxs)
	errv := versionPQueue.Enqueue(2, NewMessageBytes(kntxs))
	if(errv != nil){
		log.Panic(errv)
	}*/

	delete(ps.Peers, id)
	p.close()

	return nil
}

// Peer retrieves the registered peer with the given id.
func (ps *peerSet) Peer(id string) *Peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.Peers[id]
}

// Len returns if the current number of peers in the set.
func (ps *peerSet) Len() int {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return len(ps.Peers)
}

// PeersWithoutBlock retrieves a list of peers that do not have a given block in
// their set of known hashes.
func (ps *peerSet) PeersWithoutBlock(hash []byte) []*Peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*Peer, 0, len(ps.Peers))
	for _, p := range ps.Peers {
		if !p.knownBlocks.Has(hex.EncodeToString(hash)) {
			list = append(list, p)
		}
	}
	return list
}

// PeersWithoutTx retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
func (ps *peerSet) PeersWithoutTx(hash []byte) []*Peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*Peer, 0, len(ps.Peers))
	for _, p := range ps.Peers {
		fmt.Println("---------> p.knownTxs.Has:", hex.EncodeToString(hash))
		if !p.knownTxs.Has(hex.EncodeToString(hash)) {
			list = append(list, p)
		}
	}
	return list
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (ps *peerSet) Close() {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	for _, p := range ps.Peers {
		p.Disconnect(p2p.DiscQuitting)
	}
	ps.closed = true
}

// MarkTransaction marks a transaction as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *Peer) MarkTransaction(hash []byte) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownTxs.Size() >= maxKnownTxs {
		p.knownTxs.Pop()
	}
	p.knownTxs.Add(hex.EncodeToString(hash))
	//fmt.Println("--------->MarkTransaction p.knownTxs.Has:", hex.EncodeToString(hash),"--",p.knownTxs.Has(hex.EncodeToString(hash)))
}

// BestPeer retrieves the known peer with the currently highest total difficulty.
func (ps *peerSet) BestPeer() *Peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	var (
		bestPeer *Peer
		bestTd   *big.Int
	)
	for _, p := range ps.Peers {
		if td := p.Td; bestPeer == nil || td.Cmp(bestTd) > 0 {
			bestPeer, bestTd = p, td
		}
	}
	return bestPeer
}

func (p *Peer) broadcast() {
	for {
		select {
		case txs := <-p.queuedTxs:
			if err := p.SendTransactions(txs); err != nil {
				return
			}
			//fmt.Println("---broadcast p.queuedTxs ")
			p.Log().Trace("Broadcast transactions", "count", len(txs))

		//case prop := <-p.queuedProps:
		//	if err := p.SendNewBlock(prop.block, prop.td); err != nil {
		//		return
		//	}
		//	p.Log().Trace("Propagated block", "number", prop.block.Height, "hash", prop.block.Hash, "td", prop.td)

		case <-p.term:
			return

		}
	}
}


// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
func (p *Peer) SendTransactions(txs core.Transactions) error {
	var items = make([][]byte,0)
	for _, tx := range txs {
		p.knownTxs.Add(hex.EncodeToString(tx.Hash()))
		items = append(items,tx.ID)
	}
	//fmt.Println("--- SendTransactions  len(txs)  ",len(txs))
	//fmt.Println("--- SendTransactions  len(items) 0 ",len(items))
	//return p2p.Send(p.Rw, TxMsg, txs)
	return sendInv(p.Rw,"tx", items)
}


// SendNewBlock propagates an entire block to a remote peer.
func (p *Peer) SendNewBlock(block *core.Block, td *big.Int) error {
	p.knownBlocks.Add(hex.EncodeToString(block.Hash.Bytes()))
	//return p2p.Send(p.Rw, NewBlockMsg, []interface{}{block, td})
	return sendBlock(p.Rw,block)
}

// AsyncSendNewBlock queues an entire block for propagation to a remote peer. If
// the peer's broadcast queue is full, the event is silently dropped.
func (p *Peer) AsyncSendNewBlock(block *core.Block, td *big.Int) {
	select {
	case p.queuedProps <- &propEvent{block: block, td: td}:
		p.knownBlocks.Add(hex.EncodeToString(block.Hash.Bytes()))
	default:
		p.Log().Debug("Dropping block propagation", "number", block.Height, "hash", block.Hash)
	}
}

// AsyncSendTransactions queues list of transactions propagation to a remote
// peer. If the peer's broadcast queue is full, the event is silently dropped.
func (p *Peer) AsyncSendTransactions(txs []*core.Transaction) {
	select {
	case p.queuedTxs <- txs:
		fmt.Println("---p.queuedTxs:",len(txs))
		for _, tx := range txs {
			p.MarkTransaction(tx.ID)
			//p.knownTxs.Add(hex.EncodeToString(tx.ID))
		}
	default:
		fmt.Println("Dropping transaction propagation:",len(txs))
		p.Log().Debug("Dropping transaction propagation", "count", len(txs))
	}
}

// close signals the broadcast goroutine to terminate.
func (p *Peer) close() {
	close(p.term)
}

