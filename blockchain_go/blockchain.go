package core

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/boltdb/bolt"
	"strings"
	"math/big"
	"crypto/sha256"
)

const dbFile = "blockchain_%s.db"
const blocksBucket = "blocks"
const genesisCoinbaseData = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

const halfRewardblockCount = 210000

// Blockchain implements interactions with a DB
type Blockchain struct {
	tip []byte
	Db  *bolt.DB
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
	if dbExists(dbFile) {
		fmt.Println("Blockchain already exists.")
		os.Exit(1)
	}

	var tip []byte

	cbtx := NewCoinbaseTX(address, genesisCoinbaseData)
	genesis := NewGenesisBlock(cbtx)

	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte(blocksBucket))
		if err != nil {
			log.Panic(err)
		}

		err = b.Put(genesis.Hash, genesis.Serialize())
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), genesis.Hash)
		if err != nil {
			log.Panic(err)
		}
		tip = genesis.Hash

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	bc := Blockchain{tip, db}
	return &bc
}

// NewBlockchain creates a new Blockchain with genesis Block
func NewBlockchain(nodeID string) *Blockchain {
	var dbFile = genBlockChainDbName(nodeID)
	if dbExists(dbFile) == false {
		fmt.Println("No existing blockchain found. Create one first.")
		os.Exit(1)
	}

	var tip []byte
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		tip = b.Get([]byte("l"))

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	bc := Blockchain{tip, db}

	return &bc
}

// AddBlock saves the block into the blockchain
func (bc *Blockchain) AddBlock(block *Block) {
	err := bc.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		blockInDb := b.Get(block.Hash)

		if blockInDb != nil {
			return nil
		}

		blockData := block.Serialize()
		err := b.Put(block.Hash, blockData)
		if err != nil {
			log.Panic(err)
		}

		lastHash := b.Get([]byte("l"))
		lastBlockData := b.Get(lastHash)
		lastBlock := DeserializeBlock(lastBlockData)

		if block.Height > lastBlock.Height {
			err = b.Put([]byte("l"), block.Hash)
			if err != nil {
				log.Panic(err)
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

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	return Transaction{}, errors.New("Transaction is not found")
}

// FindUTXO finds all unspent transaction outputs and returns transactions with spent outputs removed
func (bc *Blockchain) FindUTXO() map[string]TXOutputs {
	UTXO := make(map[string]TXOutputs)
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
							continue Outputs
						}
					}
				}

				outs := UTXO[txID]
				outs.Outputs = append(outs.Outputs, out)
				UTXO[txID] = outs
			}

			if tx.IsCoinbase() == false {
				for _, in := range tx.Vin {
					inTxID := hex.EncodeToString(in.Txid)
					spentTXOs[inTxID] = append(spentTXOs[inTxID], in.Vout)
				}
			}
		}

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	return UTXO
}

// Iterator returns a BlockchainIterat
func (bc *Blockchain) Iterator() *BlockchainIterator {
	bci := &BlockchainIterator{bc.tip, bc.Db}

	return bci
}

// GetBestHeight returns the height of the latest block
func (bc *Blockchain) GetBestHeight() (int,string) {
	var lastBlock Block

	err := bc.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash := b.Get([]byte("l"))
		blockData := b.Get(lastHash)
		lastBlock = *DeserializeBlock(blockData)

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return lastBlock.Height,hex.EncodeToString(lastBlock.Hash)
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

// GetBlockHashes returns a list of hashes of all the blocks after a block in the chain
func (bc *Blockchain) GetBlockHashes(lastHash string) [][]byte {
	var blocks [][]byte
	bci := bc.Iterator()

	stopBlock := false
	for {
		block := bci.Next()
		fmt.Printf("--------->GetBlockHashes 1 len(block.PrevBlockHash) %s\n", len(block.PrevBlockHash))
		if len(block.PrevBlockHash) == 0 {
			break
		}
		fmt.Printf("--------->GetBlockHashes 2 lastHash %s\n", lastHash)
		if(lastHash == hex.EncodeToString(block.Hash)) {
			stopBlock = true
			continue
		}
		fmt.Printf("--------->GetBlockHashes 3 stopBlock %s\n", stopBlock)
		if(!stopBlock){
			blocks = append(blocks, block.Hash)
		}

	}
	fmt.Printf("prepare blocks with %d \n", len(blocks))

	return blocks
}

// MineBlock mines a new block with the provided transactions
func (bc *Blockchain) MineBlock(transactions []*Transaction) *Block {
	var lastHash []byte
	var lastHeight int
	var validTransactions []*Transaction
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

	for _, tx := range transactions {
		// TODO: ignore transaction if it's not valid
		// 1 have received longest chain among knownodes(full nodes)
		// 2 transaction have valid sign accounding to owner's pubkey by VerifyTransaction()
		// 3 utxo amount >= transaction output amount
		// 4 transaction from address not equal to address
		var valid1 = true
		var valid2 = true
		var valid3 = true
		if !bc.VerifyTransaction(tx) {
			log.Panic("ERROR: Invalid transaction:sign")
			valid1 = false
		}
		UTXOSet := UTXOSet{bc}
		if(tx.IsCoinbase()==false&&!UTXOSet.isUTXOAmountValid(tx)){
			log.Panic("ERROR: Invalid transaction:amount")
			valid2 = false
		}
		valid3 = VeryfyFromToAddress(tx)
		if(valid1 && valid2 && valid3){
			validTransactions = append(validTransactions,tx)
		}
		fmt.Printf("valid3  %s\n", valid3)


	}
	fmt.Printf("len(validTransactions)  %d \n", len(validTransactions))
	if(len(validTransactions) == 0){
		return nil
	}

	newBlock := NewBlock(validTransactions, lastHash, lastHeight+1)

	err = bc.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		err := b.Put(newBlock.Hash, newBlock.Serialize())
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), newBlock.Hash)
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
}

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

func dbExists(dbFile string) bool {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return false
	}

	return true
}

// make sure block is valid by checking height, and comparing the hash of the previous block
// ,and block hash,and block pow result,and transaction consistent(time line,utxo,tx address,coinbasetx)
func (bc *Blockchain)IsBlockValid(newBlock *Block) (bool,int) {
	var oldBlock *Block
	var lastHashS string
	var reason = 0
	err := bc.Db.View(func(tx *bolt.Tx) (error) {
		b := tx.Bucket([]byte(blocksBucket))
		blockInDb := b.Get(newBlock.Hash)

		if blockInDb != nil {
			return nil
		}

		lastHash := b.Get([]byte("l"))
		lastHashS = hex.EncodeToString(lastHash[:])
		fmt.Printf("lastHash %s \n", lastHashS)
		lastBlockData := b.Get(lastHash)
		oldBlock = DeserializeBlock(lastBlockData)

		return nil
	})

	if err != nil {
		log.Panic(err)
	}
	if(oldBlock==nil){
		fmt.Printf("newBlock.Hash:%x",newBlock.Hash)
		log.Panic("last block inconsistent with new block!lastHashS:"+lastHashS)
		reason = 1
	}
	//fmt.Printf("oldBlock.Height %n \n", oldBlock.Height)
	//fmt.Printf("newBlock.Height %n \n", newBlock.Height)
	if oldBlock.Height+1 != newBlock.Height {
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
	if(!UTXOSet.VerifyTxTimeLineAndUTXOAmount(oldBlock.Timestamp,newBlock)){
		reason = 6
		return false,reason
	}
	for _,tx := range newBlock.Transactions{
		if(!VeryfyFromToAddress(tx)){
			reason = 7
			return false,reason
		}
	}
	return true,reason
}

func prepareData(block *Block)[]byte{
	data := bytes.Join(
		[][]byte{
			block.PrevBlockHash,
			block.HashTransactions(),
			IntToHex(block.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(int64(block.Nonce)),
		},
		[]byte{},
	)
	return data
}

// SHA256 hashing
func calculateHash(block *Block) ([]byte,*ProofOfWork) {
	//record := prepareData(block)
	//hashed := sha256.Sum256(record)
	var hash [32]byte
	pow := NewProofOfWork(block)
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
