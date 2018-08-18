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
	"github.com/ethereum/go-ethereum/common"
	"../blockchain_go/rawdb"
)

const dbFile = "blockchain_%s.db"
const blocksBucket = "blocks"
const genesisCoinbaseData = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

const halfRewardblockCount = 210000

// Blockchain implements interactions with a DB
type Blockchain struct {
	GenesisHash common.Hash
	tip common.Hash
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

	var tip common.Hash
	var genesisHash common.Hash

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

		err = b.Put(genesis.Hash.Bytes(), genesis.Serialize())
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), genesis.Hash.Bytes())
		if err != nil {
			log.Panic(err)
		}
		tip = genesis.Hash

		err = b.Put([]byte("g"), genesis.Hash.Bytes())
		if err != nil {
			log.Panic(err)
		}
		genesisHash = genesis.Hash
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	rawdb.WriteCanonicalHash(db,genesis.Hash,0)

	bc := Blockchain{genesisHash,tip, db}
	return &bc
}

// NewBlockchain creates a new Blockchain with genesis Block
func NewBlockchain(nodeID string) *Blockchain {
	var dbFile = genBlockChainDbName(nodeID)
	if dbExists(dbFile) == false {
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

	bc := Blockchain{genesisHash,tip, db}

	return &bc
}

// AddBlock saves the block into the blockchain
func (bc *Blockchain) AddBlock(block *Block) {
	err := bc.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		blockInDb := b.Get(block.Hash.Bytes())

		if blockInDb != nil {
			return nil
		}

		blockData := block.Serialize()
		err := b.Put(block.Hash.Bytes(), blockData)
		if err != nil {
			log.Panic(err)
		}

		lastHash := b.Get([]byte("l"))
		lastBlockData := b.Get(lastHash)
		lastBlock := DeserializeBlock(lastBlockData)

		if block.Height.Cmp(lastBlock.Height) > 0 {
			err = b.Put([]byte("l"), block.Hash.Bytes())
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

		if bytes.Equal(block.PrevBlockHash.Bytes(),common.BytesToHash([]byte{}).Bytes())  {
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
		log.Panic("last block inconsistent with new block!lastHashS:"+lastHashS)
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