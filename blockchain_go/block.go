package core

import (
	"bytes"
	"encoding/gob"
	"log"
	"time"
	"fmt"
	"math/big"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/crypto/sha3"
)

// Some weird constants to avoid constant memory allocs for them.
var (
	expDiffPeriod = big.NewInt(100000)
	big1          = big.NewInt(1)
	big2          = big.NewInt(2)
	big4          = big.NewInt(4)
	big9          = big.NewInt(9)
	big10         = big.NewInt(10)
	bigMinus99    = big.NewInt(-99)
	big2999999    = big.NewInt(2999999)
)

var (
	DifficultyBoundDivisor = big.NewInt(10)   // The bound divisor of the difficulty, used in the update calculations.
	GenesisDifficulty      = big.NewInt(12) // Difficulty of the Genesis block.
	MinimumDifficulty      = big.NewInt(12) // The minimum that the difficulty may ever be.
	DurationLimit          = big.NewInt(13)     // The decision boundary on the blocktime duration used to determine whether difficulty should go up or not.
)

// Block represents a block in the blockchain
type Block struct {
	Timestamp     *big.Int
	Transactions  []*Transaction
	PrevBlockHash common.Hash
	Hash          common.Hash
	Nonce         int
	Height        *big.Int
	Difficulty    *big.Int
	ReceivedAt    time.Time
}

// NewBlock creates and returns Block
func NewBlock(transactions []*Transaction, prevBlockHash []byte, height *big.Int,genesis bool,bc *Blockchain) *Block {
	var dif *big.Int
	timetime := time.Now()
	time64 := timetime.Unix()
	time := new(big.Int).SetInt64(time64)
	if (!genesis && bc != nil) {
		preBlock, _ := bc.GetBlock(prevBlockHash)
		dif = CalcDifficulty(time.Uint64(), &preBlock)
	}else{
		dif = big4
	}

	block := &Block{ time, transactions, common.BytesToHash(prevBlockHash), common.BytesToHash([]byte{}), 0, height,dif, timetime}
	pow := NewProofOfWork(block,dif.Int64())
	nonce, hash := pow.Run()


	block.Hash = common.BytesToHash(hash)
	block.Nonce = nonce

	fmt.Printf("mined Block  %s \n", block)
	return block
}

func (b *Block)NumberU64()uint64{
	return b.Height.Uint64()
}
func (b *Block)Root()common.Hash{
	return b.Hash
}

// NewGenesisBlock creates and returns genesis Block
func NewGenesisBlock(coinbase *Transaction) *Block {
	return NewBlock([]*Transaction{coinbase}, []byte{}, big.NewInt(0),true,nil)
}

// HashTransactions returns a hash of the transactions in the block
func (b *Block) GetTransactions() []*Transaction {
	var transactions []*Transaction
	for _, tx := range b.Transactions {
		transactions = append(transactions, tx)
	}
	return transactions
}

// HashTransactions returns a hash of the transactions in the block
func (b *Block) HashTransactions() []byte {
	var transactions [][]byte

	for _, tx := range b.Transactions {
		//transactions = append(transactions, tx.Serialize())
		//transactions = append(transactions, tx.Hash())
		transactions = append(transactions, []byte(tx.String()))
	}
	mTree := NewMerkleTree(transactions)

	return mTree.RootNode.Data
}


func rlpHash(x interface{}) (h common.Hash) {
	/*d := []byte{}
	d,_ = rlp.EncodeToBytes(x)
	log.Println("---encoded  rlp :",d)
	var hash256 = sha256.Sum256(d)
	log.Println("---encoded  rlp hash256:",hash256)*/
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

// Serialize serializes the block
func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	gob.Register(b.Hash)
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(b)
	if err != nil {
		log.Panic(err)
	}

	return result.Bytes()
}

// DeserializeBlock deserializes a block
func DeserializeBlock(d []byte) *Block {
	var block Block

	fmt.Printf("len(d) 1 %d \n", len(d))
	//fmt.Printf("d 1 %s \n", d)
	gob.Register(common.Hash{})
	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panic(err)
	}

	return &block
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
//func (b *Block) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
func (b *Block) CalcDifficulty(time uint64, parent *Block) *big.Int {
	return CalcDifficulty(time, parent)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
//func CalcDifficulty(config *params.ChainConfig, time uint64, parent *types.Header) *big.Int {
func CalcDifficulty(time uint64, parent *Block) *big.Int {
	//next := new(big.Int).Add(parent.Number, big1)
	//switch {
	//case config.IsByzantium(next):
		//return calcDifficultyByzantium(time, parent)
	//case config.IsHomestead(next):
		return calcDifficultyHomestead(time, parent)
	//default:
	//	return calcDifficultyFrontier(time, parent)
	//}
}


// calcDifficultyHomestead is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time given the
// parent block's time and difficulty. The calculation uses the Homestead rules.
func calcDifficultyHomestead(time uint64, parent *Block) *big.Int {
	// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
	// algorithm:
	// diff = (parent_diff +
	//         (parent_diff / 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99))
	//        ) + 2^(periodCount - 2)

	bigTime := new(big.Int).SetUint64(time)
	bigParentTime := new(big.Int).Set(parent.Timestamp)

	// holds intermediate values to make the algo easier to read & audit
	x := new(big.Int)
	y := new(big.Int)

	// 1 - (block_timestamp - parent_timestamp) // 10
	x.Sub(bigTime, bigParentTime)
	fmt.Printf("(block_timestamp - parent_timestamp) == %d \n", x.Int64())
	x.Div(x, big10)
	x.Sub(big1, x)
	fmt.Printf("1 - (block_timestamp - parent_timestamp) // 10 == %d \n", x.Int64())

	// max(1 - (block_timestamp - parent_timestamp) // 10, -99)
	if x.Cmp(bigMinus99) < 0 {
		x.Set(bigMinus99)
	}
	fmt.Printf("max(1 - (block_timestamp - parent_timestamp) // 10,-99) == %d \n", x.Int64())
	// (parent_diff + parent_diff // 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99))
	y.Div(parent.Difficulty, DifficultyBoundDivisor)
	fmt.Printf("parent_diff // %d   %d \n", DifficultyBoundDivisor,y.Int64())
	x.Mul(y, x)
	fmt.Printf("parent_diff  %d \n", parent.Difficulty)
	fmt.Printf("parent_diff // %d * max == %d \n", DifficultyBoundDivisor,x.Int64())
	x.Add(parent.Difficulty, x)
	fmt.Printf("parent_diff + parent_diff // %d * max == %d \n", DifficultyBoundDivisor,x.Int64())

	// minimum difficulty can ever be (before exponential factor)
	if x.Cmp(MinimumDifficulty) < 0 {
		x.Set(MinimumDifficulty)
	}
	fmt.Printf("x.Set(params.MinimumDifficulty) == %d \n", x.Int64())
	// for the exponential factor
	periodCount := new(big.Int).Add(parent.Height, big1)
	periodCount.Div(periodCount, expDiffPeriod)
	fmt.Printf("(parent.Height+1)//10000 == %d \n", periodCount.Int64())

	// the exponential factor, commonly referred to as "the bomb"
	// diff = diff + 2^(periodCount - 2)
	if periodCount.Cmp(big1) > 0 {
		y.Sub(periodCount, big2)
		y.Exp(big2, y, nil)
		x.Add(x, y)
		fmt.Printf("diff = diff + 2^(periodCount - 2) == %d \n", x.Int64())
	}
	fmt.Printf("diff = diff + 2^(periodCount - 2) == %d \n", x.Int64())
	return x
}


// Hashransactions returns a has of the transactions in the block
func (b *Block) HasTransactions(TxId []byte) bool{

	for _, tx := range b.Transactions {
		//transactions = append(transactions, tx.Serialize())
		//transactions = append(transactions, tx.Hash())
		if(bytes.Equal(tx.ID,TxId)){
			return true
		}
	}

	return false
}