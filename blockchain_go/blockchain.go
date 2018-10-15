package core

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/boltdb/bolt"
	"strings"
	"math/big"
	"crypto/sha256"
	"github.com/ethereum/go-ethereum/common"
	"../blockchain_go/rawdb"
	."../boltqueue"
	."./state"
	/*"time"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/common/mclock"
	"sync/atomic"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"*/
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/core/types"
	"./state"
)

const dbFile = "blockchain_%s.db"
const blocksBucket = "blocks"
const genesisCoinbaseData = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

const halfRewardblockCount = 2100000


var ErrNotEnoughFunds = errors.New("not enough funds")


// Blockchain implements interactions with a DB
type Blockchain struct {
	GenesisHash common.Hash
	tip common.Hash
	Db  *bolt.DB
	//stateCache   state.Database // State database to reuse between imports (contains state cache)
	stateCache  *bolt.DB

	chainHeadFeed event.Feed
	scope         event.SubscriptionScope

	NodeId string
}

func genBlockChainDbName(nodeID string)string{
	nodeID = strings.Replace(nodeID, ":", "_", -1)
	dbFile := fmt.Sprintf(dbFile, nodeID)

	return dbFile;
}

// CreateBlockchain creates a new blockchain DB
func CreateBlockchain(address, nodeID string) *Blockchain {
	dbFile := genBlockChainDbName(nodeID)
	fmt.Printf("Blockchain file %s\n",dbFile)
	if DbExists(dbFile) {
		fmt.Println("Blockchain already exists.")
		os.Exit(1)
	}

	var tip common.Hash
	var genesisHash common.Hash

	statedb, _ := state.New(common.Hash{}, nil,nodeID)
	var addr = Base58ToCommonAddress([]byte(address))
	statedb.AddBalance(addr, big.NewInt(subsidy))
	/*statedb.SetCode(addr, account.Code)*/
	statedb.SetNonce(addr, 0)
	/*for key, value := range account.Storage {
		statedb.SetState(addr, key, value)
	}*/
	cbtx := NewCoinbaseTX(0,address, genesisCoinbaseData,nodeID)
	genesis := NewGenesisBlock(cbtx)

	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte(blocksBucket))
		if err != nil {
			//log.Panic(err)
			return err
		}

		err = b.Put(genesis.Hash.Bytes(), genesis.Serialize())
		if err != nil {
			//log.Panic(err)
			return err
		}

		err = b.Put([]byte("l"), genesis.Hash.Bytes())
		if err != nil {
			//log.Panic(err)
			return err
		}
		tip = genesis.Hash

		err = b.Put([]byte("g"), genesis.Hash.Bytes())
		if err != nil {
			//log.Panic(err)
			return err
		}
		genesisHash = genesis.Hash
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	rawdb.WriteCanonicalHash(db,genesis.Hash,0)

	bc := &Blockchain{
		GenesisHash:genesisHash,
		tip:tip,
		Db:db,
		NodeId:nodeID,
	}
	return bc
}

// NewBlockchain creates a new Blockchain with genesis Block
func NewBlockchain(nodeID string) *Blockchain {
	var dbFile = genBlockChainDbName(nodeID)
	fmt.Printf("Blockchain file %s\n",dbFile)
	if DbExists(dbFile) == false {
		fmt.Println("No existing blockchain found. Create one first.")
		os.Exit(1)
	}

	fmt.Println("--- bf Open dbFile:")
	var tip common.Hash
	var genesisHash common.Hash
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	fmt.Println("--- bf db.View:")
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		tip = common.BytesToHash(b.Get([]byte("l")))
		genesisHash = common.BytesToHash(b.Get([]byte("g")))
		return nil
	})
	if err != nil {
		log.Panic(err)
	}


	bc := &Blockchain{
		GenesisHash:genesisHash,
		tip:tip,
		Db:db,
		NodeId:nodeID,
	}

	return bc
}

// AddBlock saves the block into the blockchain
func (bc *Blockchain) AddBlock(block *Block) {
	err := bc.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		blockInDb := b.Get(block.Hash.Bytes())

		if blockInDb != nil {
			return errors.New("block exist!")
		}

		blockData := block.Serialize()
		err := b.Put(block.Hash.Bytes(), blockData)
		if err != nil {
			//log.Panic(err)
			return err
		}

		lastHash := b.Get([]byte("l"))
		lastBlockData := b.Get(lastHash)
		lastBlock := DeserializeBlock(lastBlockData)

		if block.Height.Cmp(lastBlock.Height) > 0 {
			err = b.Put([]byte("l"), block.Hash.Bytes())
			if err != nil {
				//log.Panic(err)
				return err
			}
			bc.tip = block.Hash
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}

// FindTransaction finds a transaction by its ID
func (bc *Blockchain) FindTransaction(ID []byte) (Transaction, error) {
	bci := bc.Iterator()

	for {
		block := bci.Next()
		var ids = hex.EncodeToString(ID)
		fmt.Printf("tx.ID: \"%s\" \n", ids)
		for _, tx := range block.Transactions {
			if bytes.Compare(tx.ID, ID) == 0 {
				return *tx, nil
			}
		}

		if bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes())  {
			break
		}
	}

	return Transaction{}, errors.New("Transaction is not found")
}

// FindUTXO finds all unspent transaction outputs and returns transactions with spent outputs removed
func (bc *Blockchain) FindUTXO() map[string]TXOutputs {
	UTXO := make(map[string]TXOutputs)
	//TODO put spentTXOs in bucket
	spentTXOs := make(map[string][]int)
	bci := bc.Iterator()

	for {
		block := bci.Next()

		for _, tx := range block.Transactions {
			txID := hex.EncodeToString(tx.ID)

		Outputs:
			for outIdx, out := range tx.Vout {
				// Was the output spent?
				if spentTXOs[txID] != nil {
					for _, spentOutIdx := range spentTXOs[txID] {
						if spentOutIdx == outIdx {
							//continue Outputs
							outs := make([]TXOutput,0)
							UTXO[txID] = TXOutputs{outs}
							break Outputs
						}
					}
				}

				outs := UTXO[txID]
				outs.Outputs = append(outs.Outputs, out)
				UTXO[txID] = outs
			}
		//SpentTXOs:

			if tx.IsCoinbase() == false {
				for _, in := range tx.Vin {
					inTxID := hex.EncodeToString(in.Txid)
					spentTXOs[inTxID] = append(spentTXOs[inTxID], int(in.Vout.Int64()))
				}
			}
		}

		//fmt.Println("block.PrevBlockHash.Bytes() ",block.PrevBlockHash.Bytes())
		if bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes()){
			break
		}
	}

	return UTXO
}

// Iterator returns a BlockchainIterat
func (bc *Blockchain) Iterator() *BlockchainIterator {
	//fmt.Println("tip ",bc.tip)
	bci := &BlockchainIterator{bc.tip, bc.Db}

	return bci
}

// GetBestHeight returns the height of the latest block and last block hash
func (bc *Blockchain) GetBestHeightLastHash() (*big.Int,common.Hash) {
	var lastBlock Block

	err := bc.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash := b.Get([]byte("l"))
		blockData := b.Get(lastHash)
		lastBlock = *DeserializeBlock(blockData)
		//fmt.Println("bf lastBlock.Hash set value：", lastBlock.Hash)
		//lastBlock.Hash = lastHash
		//fmt.Println("af lastBlock.Hash set value：", lastBlock.Hash)
		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return lastBlock.Height,lastBlock.Hash
}

// GetBestHeight returns the height of the latest block
func (bc *Blockchain) GetBestHeight() (*big.Int,string) {
	height,lastHash:= bc.GetBestHeightLastHash()
	return height,hex.EncodeToString(lastHash.Bytes())
}

// GetBlock finds a block by its hash and returns it
func (bc *Blockchain) GetBlock(blockHash []byte) (Block, error) {
	var block Block

	err := bc.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))

		blockData := b.Get(blockHash)

		if blockData == nil {
			return errors.New("Block is not found.")
		}

		block = *DeserializeBlock(blockData)

		return nil
	})
	if err != nil {
		return block, err
	}

	return block, nil
}

// GetBlock finds a block by its hash and returns it
func (bc *Blockchain) GetBlockByHashNumber(blockHash []byte,number uint64) (*Block, error) {
	var block Block

	err := bc.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))

		blockData := b.Get(blockHash)

		if blockData == nil {
			return errors.New("Block is not found.")
		}

		block = *DeserializeBlock(blockData)

		return nil
	})
	if err != nil {
		return &block, err
	}
	if block.Height.Uint64() != number {
		return &block, errors.New("ERROR:block number not same")
	}

	return &block, nil
}

// GetBlockHashes returns a list of hashes of all the blocks after a block in the chain
func (bc *Blockchain) GetBlockHashes(lastHash string) [][]byte {
	var blocks [][]byte
	bci := bc.Iterator()

	stopBlock := false
	for {
		block := bci.Next()
		fmt.Printf("--------->GetBlockHashes 1 bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes()) %s\n", bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes()))
		if bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes())  {
			break
		}
		fmt.Printf("--------->GetBlockHashes 2 lastHash %s\n", lastHash)
		if(lastHash == hex.EncodeToString(block.Hash.Bytes())) {
			stopBlock = true
			continue
		}
		fmt.Printf("--------->GetBlockHashes 3 stopBlock %s\n", stopBlock)
		if(!stopBlock){
			blocks = append(blocks, block.Hash.Bytes())
		}
	}
	fmt.Printf("prepare blocks with %d \n", len(blocks))

	return blocks
}

// GetBlockHashes returns a list of hashes of all the blocks after a block in the chain
func (bc *Blockchain) GetBlockHashesMap(lastHash []byte) map[string][]byte {
	var blocks = make(map[string][]byte)
	bci := bc.Iterator()

	stopBlock := false
	for {
		block := bci.Next()
		fmt.Printf("--------->GetBlockHashes 1 bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes()) %s\n", bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes()))
		if bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes())  {
			break
		}
		fmt.Printf("--------->GetBlockHashes 2 lastHash %x\n", lastHash)
		if(bytes.Equal(lastHash,block.Hash.Bytes())) {
			stopBlock = true
			continue
		}
		hashstr := hex.EncodeToString(block.Hash.Bytes())
		fmt.Printf("--------->GetBlockHashes 3 stopBlock %s\n", stopBlock)
		if(!stopBlock){
			blocks[hashstr] = block.Hash.Bytes()
		}
	}
	fmt.Printf("prepare blocks with %d \n", len(blocks))

	return blocks
}

// MineBlock mines a new block with the provided transactions
func (bc *Blockchain) MineBlock(transactions []*Transaction) *Block {
	var lastHash []byte
	var lastHeight *big.Int
	var block *Block
	err := bc.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash = b.Get([]byte("l"))

		blockData := b.Get(lastHash)
		block = DeserializeBlock(blockData)

		lastHeight = block.Height

		return nil
	})

	if err != nil {
		log.Panic(err)
	}


	x := new(big.Int)
	newBlock := NewBlock(transactions, lastHash, x.Add(lastHeight,big1), false,bc)

	err = bc.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		err := b.Put(newBlock.Hash.Bytes(), newBlock.Serialize())
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), newBlock.Hash.Bytes())
		if err != nil {
			log.Panic(err)
		}

		bc.tip = newBlock.Hash

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return newBlock
}
/*
// SignTransaction signs inputs of a Transaction
func (bc *Blockchain) SignTransaction(tx *Transaction, privKey ecdsa.PrivateKey) {
	prevTXs := make(map[string]Transaction)

	for _, vin := range tx.Vin {
		prevTX, err := bc.FindTransaction(vin.Txid)
		if err != nil {
			log.Panic(err)
		}
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}

	tx.Sign(privKey, prevTXs)
}*/

// VerifyTransaction verifies transaction input signatures
func (bc *Blockchain) VerifyTransaction(tx *Transaction) bool {
	if tx.IsCoinbase() {
		return true
	}

	prevTXs := make(map[string]Transaction)

	for _, vin := range tx.Vin {
		prevTX, err := bc.FindTransaction(vin.Txid)
		if err != nil {
			log.Panic(err)
		}
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}

	return tx.Verify(prevTXs)

}


// make sure block is valid by checking height, and comparing the hash of the previous block
// ,and block hash,and block pow result,and transaction consistent(time line,utxo,tx address,coinbasetx)
func (bc *Blockchain)IsBlockValid(newBlock *Block) (bool,int) {
	var oldBlock *Block
	var lastHashS string
	var reason = 0
	err := bc.Db.View(func(tx *bolt.Tx) (error) {
		b := tx.Bucket([]byte(blocksBucket))
		blockInDb := b.Get(newBlock.Hash.Bytes())

		if blockInDb != nil {
			return nil
		}

		lastHash := b.Get([]byte("l"))
		lastHashS = hex.EncodeToString(lastHash[:])
		fmt.Printf("lastHash %x \n", lastHashS)
		lastBlockData := b.Get(lastHash)
		oldBlock = DeserializeBlock(lastBlockData)

		return nil
	})

	if err != nil {
		log.Panic(err)
	}
	if(oldBlock==nil){
		fmt.Printf("newBlock.Hash:%x",newBlock.Hash)
		log.Panic("ERROR:last block inconsistent with new block!lastHashS:"+lastHashS)
		reason = 1
	}
	//fmt.Printf("oldBlock.Height %n \n", oldBlock.Height)
	//fmt.Printf("newBlock.Height %n \n", newBlock.Height)
	x := new(big.Int)
	if x.Add(oldBlock.Height,big1).Cmp(newBlock.Height) !=0 {
		reason = 2
		return false,reason
	}

	if lastHashS != hex.EncodeToString(newBlock.PrevBlockHash[:]) {
		reason = 3
		return false,reason
	}

	//fmt.Printf("newBlock %s \n", newBlock)
	newHashA,pow := calculateHash(newBlock)
	newHash := hex.EncodeToString(newHashA[:])
	//fmt.Printf("calculateHash(newBlock) %s \n", newHash)
	//fmt.Printf("newBlock.hash %s \n", hex.EncodeToString(newBlock.Hash[:]))
	if newHash != hex.EncodeToString(newBlock.Hash[:]) {
		reason = 4
		return false,reason
	}

	//pow validate
	var hashInt big.Int
	hashInt.SetBytes(newHashA[:])
	if hashInt.Cmp(pow.target) != -1 {
		reason = 5
		return false,reason
	}

	//transaction consistent validate
	UTXOSet := UTXOSet{bc}
	queueFile := GenWalletStateDbName(bc.NodeId)
	txPQueue, errcq := NewPQueue(queueFile)
	if errcq != nil {
		log.Panic("create queue error", errcq)
	}
	defer txPQueue.Close()
	valid,reason := UTXOSet.VerifyTxTimeLineAndUTXOAmount(oldBlock.Timestamp,newBlock,txPQueue)
	log.Printf("--af  VerifyTxTimeLineAndUTXOAmount valid: %s \n",valid)
	if(!valid){
		//reason = 6
		return false,reason
	}else{
		//delete outdated vin txid in database
		for _,tx1 := range newBlock.Transactions{
			for _,in := range tx1.Vin{
				//delete vin tx id
				txPQueue.DeleteMsg(4,in.Txid)
			}
		}
	}
	//txPQueue.Close()
	for _,tx := range newBlock.Transactions{
		if(!VeryfyFromToAddress(tx)){
			reason = 7
			return false,reason
		}
	}
	return true,reason
}
/*
func prepareData(block *Block)[]byte{
	data := bytes.Join(
		[][]byte{
			block.PrevBlockHash,
			block.HashTransactions(),
			IntToHex(block.Timestamp.Int64()),
			IntToHex(int64(block.Difficulty.Int64())),
			IntToHex(int64(block.Nonce)),
		},
		[]byte{},
	)
	return data
}*/

// SHA256 hashing
func calculateHash(block *Block) ([]byte,*ProofOfWork) {
	//record := prepareData(block)
	//hashed := sha256.Sum256(record)
	var hash [32]byte
	pow := NewProofOfWork(block,block.Difficulty.Int64())
	data := pow.prepareData(block.Nonce)
	hash = sha256.Sum256(data)
	/*
	for _, tx := range pow.block.Transactions {
		fmt.Printf("tx.input   %x \n", tx.Vin)
		fmt.Printf("tx.output   %x \n", tx.Vout)
		fmt.Printf("tx.id %x \n", tx.ID)
		fmt.Printf("tx.Serialize   %x \n", tx.Serialize())
		fmt.Printf("tx.hash   %x \n", tx.Hash())
	}
	fmt.Printf("newBlock.PrevBlockHash %s \n", hex.EncodeToString(block.PrevBlockHash[:]))
	fmt.Printf("newBlock.PrevBlockHash %s \n", hex.EncodeToString(block.HashTransactions()))
	fmt.Printf("newBlock.PrevBlockHash %s \n", block.Timestamp)
	fmt.Printf("newBlock.PrevBlockHash %s \n", int64(targetBits))
	fmt.Printf("newBlock.PrevBlockHash %s \n", int64(block.Nonce))
	fmt.Printf("newBlock.PrevBlockHash %x \n", sha256.Sum256(IntToHex(int64(block.Nonce))))
	*/
	fmt.Printf("calculateHash Blockdata len %n \n", len(data))
	return hash[:],pow
}

//func GetTd(blockHash []byte)big.Int{

//}

// Delete Blocks returns a list of hashes of all the blocks after a block in the chain
func (bc *Blockchain) DelBlockHashes(hashs map[string][]byte) [][]byte {
	var blocks [][]byte
	bci := bc.Iterator()

	for{
		block := bci.Next()
		if bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes())  {
			break
		}
		if _, ok := hashs[hex.EncodeToString(block.Hash.Bytes())]; ok  {
			err := bc.Db.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucket([]byte(blocksBucket))
				if err != nil {
					log.Panic(err)
				}
				return b.Delete(block.Hash.Bytes())
			})
			if(err != nil){
				log.Panic(err)
			}
			blocks = append(blocks, block.Hash.Bytes())
		}

	}
	fmt.Printf("delete blocks with %d \n", len(blocks))

	return blocks
}

func (bc *Blockchain) CurrentBlock() *Block {
	// GetBestHeight returns the height of the latest block and last block hash
	var lastBlock Block

	fmt.Println(" current block：")
	err := bc.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash := b.Get([]byte("l"))
		blockData := b.Get(lastHash)
		lastBlock = *DeserializeBlock(blockData)
		fmt.Println("current block 1：",lastBlock.Hash)
		//fmt.Println("bf lastBlock.Hash set value：", lastBlock.Hash)
		//lastBlock.Hash = lastHash
		//fmt.Println("af lastBlock.Hash set value：", lastBlock.Hash)
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("current block 2：",lastBlock.Height.String())
	return &lastBlock
}


func (bc *Blockchain) GetBlockByNumber(number uint64) *Block {
	// GetBestHeight returns the height of the latest block and last block hash
	var lastBlock Block
	fmt.Println("block number ：", number)
	hash := rawdb.ReadCanonicalHash(bc.Db, number)
	fmt.Println("block hash ：", hash)
	if hash == (common.Hash{}) {
		return nil
	}

	err := bc.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		blockData := b.Get(hash.Bytes())
		lastBlock = *DeserializeBlock(blockData)
		//fmt.Println("bf lastBlock.Hash set value：", lastBlock.Hash)
		//lastBlock.Hash = lastHash
		//fmt.Println("af lastBlock.Hash set value：", lastBlock.Hash)
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return &lastBlock
}

func (bc *Blockchain)GetBalance(address common.Address, nodeID string)*big.Int{
	UTXOSet := UTXOSet{bc}
	defer bc.Db.Close()

	balance := big.NewInt(0)
	//pubKeyHash := Base58Decode([]byte(address))
	//pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]
	pubKeyHash := address.Bytes()

	UTXOs := UTXOSet.FindUTXO(pubKeyHash)

	for _, out := range UTXOs {
		balance.Add(big.NewInt(balance.Int64()),
			big.NewInt(int64(out.Value)))
	}
	return balance
}


// InsertChain attempts to insert the given batch of blocks in to the canonical
// chain or, otherwise, create a fork. If an error is returned it will return
// the index number of the failing block as well an error describing what went
// wrong.
//
// After insertion is done, all accumulated events will be fired.
/*func (bc *Blockchain) InsertChain(chain []Block) (int, error) {
	n, events, logs, err := bc.insertChain(chain)
	bc.PostChainEvents(events, logs)
	return n, err
}

// insertChain will execute the actual chain insertion and event aggregation. The
// only reason this method exists as a separate one is to make locking cleaner
// with deferred statements.
func (bc *Blockchain) insertChain(chain []Block) (int, []interface{}, []*types.Log, error) {
	// Sanity check that we have something meaningful to import
	if len(chain) == 0 {
		return 0, nil, nil, nil
	}
	// Do a sanity check that the provided chain is actually ordered and linked
	for i := 1; i < len(chain); i++ {
		if chain[i].NumberU64() != chain[i-1].NumberU64()+1 || chain[i].ParentHash() != chain[i-1].Hash() {
			// Chain broke ancestry, log a messge (programming error) and skip insertion
			log.Error("Non contiguous block insert", "number", chain[i].Number(), "hash", chain[i].Hash(),
				"parent", chain[i].ParentHash(), "prevnumber", chain[i-1].Number(), "prevhash", chain[i-1].Hash())

			return 0, nil, nil, fmt.Errorf("non contiguous insert: item %d is #%d [%x…], item %d is #%d [%x…] (parent [%x…])", i-1, chain[i-1].NumberU64(),
				chain[i-1].Hash().Bytes()[:4], i, chain[i].NumberU64(), chain[i].Hash().Bytes()[:4], chain[i].ParentHash().Bytes()[:4])
		}
	}
	// Pre-checks passed, start the full block imports
	bc.wg.Add(1)
	defer bc.wg.Done()

	bc.chainmu.Lock()
	defer bc.chainmu.Unlock()

	// A queued approach to delivering events. This is generally
	// faster than direct delivery and requires much less mutex
	// acquiring.
	var (
		stats         = insertStats{startTime: mclock.Now()}
		events        = make([]interface{}, 0, len(chain))
		lastCanon     *types.Block
		coalescedLogs []*types.Log
	)
	// Start the parallel header verifier
	headers := make([]*types.Header, len(chain))
	seals := make([]bool, len(chain))

	for i, block := range chain {
		headers[i] = block.Header()
		seals[i] = true
	}
	abort, results := bc.engine.VerifyHeaders(bc, headers, seals)
	defer close(abort)

	// Start a parallel signature recovery (signer will fluke on fork transition, minimal perf loss)
	senderCacher.recoverFromBlocks(types.MakeSigner(bc.chainConfig, chain[0].Number()), chain)

	// Iterate over the blocks and insert when the verifier permits
	for i, block := range chain {
		// If the chain is terminating, stop processing blocks
		if atomic.LoadInt32(&bc.procInterrupt) == 1 {
			log.Debug("Premature abort during blocks processing")
			break
		}
		// If the header is a banned one, straight out abort
		if BadHashes[block.Hash()] {
			bc.reportBlock(block, nil, ErrBlacklistedHash)
			return i, events, coalescedLogs, ErrBlacklistedHash
		}
		// Wait for the block's verification to complete
		bstart := time.Now()

		err := <-results
		if err == nil {
			err = bc.Validator().ValidateBody(block)
		}
		switch {
		case err == ErrKnownBlock:
			// Block and state both already known. However if the current block is below
			// this number we did a rollback and we should reimport it nonetheless.
			if bc.CurrentBlock().NumberU64() >= block.NumberU64() {
				stats.ignored++
				continue
			}

		case err == consensus.ErrFutureBlock:
			// Allow up to MaxFuture second in the future blocks. If this limit is exceeded
			// the chain is discarded and processed at a later time if given.
			max := big.NewInt(time.Now().Unix() + maxTimeFutureBlocks)
			if block.Time().Cmp(max) > 0 {
				return i, events, coalescedLogs, fmt.Errorf("future block: %v > %v", block.Time(), max)
			}
			bc.futureBlocks.Add(block.Hash(), block)
			stats.queued++
			continue

		case err == consensus.ErrUnknownAncestor && bc.futureBlocks.Contains(block.ParentHash()):
			bc.futureBlocks.Add(block.Hash(), block)
			stats.queued++
			continue

		case err == consensus.ErrPrunedAncestor:
			// Block competing with the canonical chain, store in the db, but don't process
			// until the competitor TD goes above the canonical TD
			currentBlock := bc.CurrentBlock()
			localTd := bc.GetTd(currentBlock.Hash(), currentBlock.NumberU64())
			externTd := new(big.Int).Add(bc.GetTd(block.ParentHash(), block.NumberU64()-1), block.Difficulty())
			if localTd.Cmp(externTd) > 0 {
				if err = bc.WriteBlockWithoutState(block, externTd); err != nil {
					return i, events, coalescedLogs, err
				}
				continue
			}
			// Competitor chain beat canonical, gather all blocks from the common ancestor
			var winner []*types.Block

			parent := bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
			for !bc.HasState(parent.Root()) {
				winner = append(winner, parent)
				parent = bc.GetBlock(parent.ParentHash(), parent.NumberU64()-1)
			}
			for j := 0; j < len(winner)/2; j++ {
				winner[j], winner[len(winner)-1-j] = winner[len(winner)-1-j], winner[j]
			}
			// Import all the pruned blocks to make the state available
			bc.chainmu.Unlock()
			_, evs, logs, err := bc.insertChain(winner)
			bc.chainmu.Lock()
			events, coalescedLogs = evs, logs

			if err != nil {
				return i, events, coalescedLogs, err
			}

		case err != nil:
			bc.reportBlock(block, nil, err)
			return i, events, coalescedLogs, err
		}
		// Create a new statedb using the parent block and report an
		// error if it fails.
		var parent *types.Block
		if i == 0 {
			parent = bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
		} else {
			parent = chain[i-1]
		}
		state, err := state.New(parent.Root(), bc.stateCache)
		if err != nil {
			return i, events, coalescedLogs, err
		}
		// Process block using the parent state as reference point.
		receipts, logs, usedGas, err := bc.processor.Process(block, state, bc.vmConfig)
		if err != nil {
			bc.reportBlock(block, receipts, err)
			return i, events, coalescedLogs, err
		}
		// Validate the state using the default validator
		err = bc.Validator().ValidateState(block, parent, state, receipts, usedGas)
		if err != nil {
			bc.reportBlock(block, receipts, err)
			return i, events, coalescedLogs, err
		}
		proctime := time.Since(bstart)

		// Write the block to the chain and get the status.
		status, err := bc.WriteBlockWithState(block, receipts, state)
		if err != nil {
			return i, events, coalescedLogs, err
		}
		switch status {
		case CanonStatTy:
			log.Debug("Inserted new block", "number", block.Number(), "hash", block.Hash(), "uncles", len(block.Uncles()),
				"txs", len(block.Transactions()), "gas", block.GasUsed(), "elapsed", common.PrettyDuration(time.Since(bstart)))

			coalescedLogs = append(coalescedLogs, logs...)
			blockInsertTimer.UpdateSince(bstart)
			events = append(events, ChainEvent{block, block.Hash(), logs})
			lastCanon = block

			// Only count canonical blocks for GC processing time
			bc.gcproc += proctime

		case SideStatTy:
			log.Debug("Inserted forked block", "number", block.Number(), "hash", block.Hash(), "diff", block.Difficulty(), "elapsed",
				common.PrettyDuration(time.Since(bstart)), "txs", len(block.Transactions()), "gas", block.GasUsed(), "uncles", len(block.Uncles()))

			blockInsertTimer.UpdateSince(bstart)
			events = append(events, ChainSideEvent{block})
		}
		stats.processed++
		stats.usedGas += usedGas

		cache, _ := bc.stateCache.TrieDB().Size()
		stats.report(chain, i, cache)
	}
	// Append a single chain head event if we've progressed the chain
	if lastCanon != nil && bc.CurrentBlock().Hash() == lastCanon.Hash() {
		events = append(events, ChainHeadEvent{lastCanon})
	}
	return 0, events, coalescedLogs, nil
}
*/

// PostChainEvents iterates over the events generated by a chain insertion and
// posts them into the event feed.
// TODO: Should not expose PostChainEvents. The chain events should be posted in WriteBlock.
func (bc *Blockchain) PostChainEvents(events []interface{}, logs []*types.Log) {
	// post event logs for further processing
	/*if logs != nil {
		bc.logsFeed.Send(logs)
	}*/
	for _, event := range events {
		switch ev := event.(type) {
		/*case ChainEvent:
			bc.chainFeed.Send(ev)
*/
		case ChainHeadEvent:
			bc.chainHeadFeed.Send(ev)
/*
		case ChainSideEvent:
			bc.chainSideFeed.Send(ev)
		}*/
		}
	}
}

func (bc *Blockchain) Events(blocks []*Block)[]interface{} {

	events        := make([]interface{}, 0, len(blocks))
	// Append a single chain head event if we've progressed the chain
	lastCanon := blocks[len(blocks)-1]
	if lastCanon != nil && bc.CurrentBlock().Hash == lastCanon.Hash {
		events = append(events, ChainHeadEvent{lastCanon})
	}
	return events
}

// SubscribeChainHeadEvent registers a subscription of ChainHeadEvent.
func (bc *Blockchain) SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription {
	return bc.scope.Track(bc.chainHeadFeed.Subscribe(ch))
}


// State returns a new mutable state based on the current HEAD block.
func (bc *Blockchain) State() (*state.WalletTransactions, error) {
	return bc.StateAt(bc.CurrentBlock().Root())
}

// StateAt returns a new mutable state based on a particular point in time.
func (bc *Blockchain) StateAt(root common.Hash) (*state.WalletTransactions, error) {
	statedb,err := state.New(root, nil,bc.NodeId)
	if(err!=nil){
		log.Println(err)
	}
	statedb.InitDB(bc.NodeId,"")
	bc.stateCache = statedb.DB
	defer statedb.DB.Close()
	return statedb,err
}