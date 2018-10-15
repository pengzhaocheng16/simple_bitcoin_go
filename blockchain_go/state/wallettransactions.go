package state

import (
	"github.com/boltdb/bolt"
	"fmt"
	"sync"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/core/types"
	//"github.com/ethereum/go-ethereum/trie"
	//"encoding/hex"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"os"
	"math/big"
	"strings"
)

const walletTransactionsBucket = "wallettransactions"
const state = "wallettransactions"
const walletTransactionsCountBucket = "wallettransactionsCount"

const walletFile = "wallet_%s.dat"
const walletStateFile = "wallet_state_%s.dat"

type revision struct {
	id           int
	journalIndex int
}
type WalletTransactions struct {
	DB *bolt.DB
	//trie trie.Trie

	// This map holds 'live' objects, which will get modified while processing a state transition.
	stateObjects      map[common.Address]*stateObject
	stateObjectsDirty map[common.Address]struct{}
	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// The refund counter, also used by state transitioning.
	refund uint64

	thash, bhash common.Hash
	txIndex      int
	logs         map[common.Hash][]*types.Log
	logSize      uint

	preimages map[common.Hash][]byte

	// Journal of state modifications. This is the backbone of
	// Snapshot and RevertToSnapshot.
	journal        *journal
	validRevisions []revision
	nextRevisionId int

	lock sync.Mutex
}

func GenWalletStateDbName(nodeID string)string{
	nodeID = GenWalletFileName(nodeID)
	walletFile := fmt.Sprintf(walletStateFile, nodeID)

	return walletFile
}

func GenWalletFileName(nodeID string)string{
	nodeID = strings.Replace(nodeID, ":", "_", -1)
	return nodeID
}

func GenWalletDbName(nodeID string)string{
	nodeID = GenWalletFileName(nodeID)
	walletFile := fmt.Sprintf(walletFile, nodeID)

	return walletFile
}

func DbExists(dbFile string) bool {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return false
	}

	return true
}

// Create a new state from a given trie.
func New(root common.Hash, db *bolt.DB) (*WalletTransactions, error) {
	/*tr, err := db.OpenTrie(root)
	if err != nil {
		return nil, err
	}*/
	return &WalletTransactions{
		DB:                db,
		//trie:              tr,
		stateObjects:      make(map[common.Address]*stateObject),
		stateObjectsDirty: make(map[common.Address]struct{}),
		logs:              make(map[common.Hash][]*types.Log),
		preimages:         make(map[common.Hash][]byte),
		journal:           newJournal(),
	}, nil
}

func (uts *WalletTransactions) InitDB(nodeId,address string) error {
	dbFile := GenWalletStateDbName(nodeId)
	fmt.Printf("wallet transaction file %s\n",dbFile)
	if DbExists(dbFile) {
		fmt.Println("wallet transaction file already exists.")
		//os.Exit(1)
	}

	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Error("InitDB","error",err)
		os.Exit(0)
	}
	uts.DB = db;

	if address != "" {
	err = uts.DB.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte(address+"_"+walletTransactionsBucket))

		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	}


	uts.stateObjects =      make(map[common.Address]*stateObject)
	uts.stateObjectsDirty = make(map[common.Address]struct{})

	return nil
}
/*
// execute functon for each key/value in the bucket
func (uts *UnapprovedTransactions) ForEach(callback ForEachKeyIteratorInterface) error {
	return uts.DB.forEachInBucket(walletTransactionsBucket, callback)
}
// get count of records in the table
func (uts *UnapprovedTransactions) GetCount() (int, error) {
	return uts.DB.Db.getCountInBucket(walletTransactionsBucket)
}
*/

func (uts *WalletTransactions) TruncateDB(address string) error {
	err := uts.DB.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(address+"_"+walletTransactionsBucket))

		if err != nil && err != bolt.ErrBucketNotFound {
			return err
		}

		_, err = tx.CreateBucket([]byte(address+"_"+walletTransactionsBucket))

		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// returns transaction by ID if it exists
func (uts *WalletTransactions) GetTransaction(txID []byte,address string) ([]byte, error) {
	var txBytes []byte

	err := uts.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(address+"_"+walletTransactionsBucket))

		if b == nil {
			return NewDBIsNotReadyError()
		}

		txBytes = b.Get(txID)

		return nil
	})
	if err != nil {
		return nil, err
	}
	return txBytes, nil
}

// Add transaction record
func (uts *WalletTransactions) PutTransaction(txID []byte, txdata []byte,address string) error {
	return uts.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(address+"_"+walletTransactionsBucket))
		if(b.Get([]byte("counter"))==nil){
			cb := make([]byte, 8)
			binary.BigEndian.PutUint64(cb, 0)
			b.Put([]byte("counter"),cb)
		}else{
			cb := b.Get([]byte("counter"))
			var x uint64
			x = uint64(binary.BigEndian.Uint64(cb[:]))
			x = x+1
			binary.BigEndian.PutUint64(cb, x)

			b.Put([]byte("counter"),cb[:])
		}

		if b == nil {
			return NewDBIsNotReadyError()
		}

		return b.Put(txID, txdata)
	})
}

// delete transation from DB
func (uts *WalletTransactions) DeleteTransaction(txID []byte,address string) error {
	return uts.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(address+"_"+walletTransactionsBucket))

		if b == nil {
			return NewDBIsNotReadyError()
		}

		return b.Delete(txID)
	})
}


// returns transaction nonce  if it exists
func (uts *WalletTransactions) GetTransactionNonce(address string) (uint64, error) {
	var nonce uint64

	err := uts.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(address+"_"+walletTransactionsBucket))

		if b == nil {
			return NewDBIsNotReadyError()
		}

		cb := b.Get([]byte("counter"))
		//to genesis block counter is empty 对于创世块
		if(len(cb) == 0){
			cb = make([]byte,8)
			binary.BigEndian.PutUint64(cb, uint64(1))
			b.Put([]byte("counter"),cb)
			nonce = uint64(1)
			return nil
		}
		nonce = uint64(binary.BigEndian.Uint64(cb))

		return nil
	})
	if err != nil {
		return 0, err
	}
	return nonce, nil
}

func (uts *WalletTransactions) TryGet(address []byte) ([]byte, error) {
	var cb []byte

	err := uts.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(state+"_"+crypto.Keccak256Hash(address[:]).String()))

		if b == nil {
			return NewDBIsNotReadyError()
		}

		cb = b.Get(address)


		return nil
	})
	if err != nil {
		return nil, err
	}
	return cb, nil
}


// Retrieve a state object or create a new state object if nil.
func (self *WalletTransactions) GetOrNewStateObject(addr common.Address) *stateObject {
	stateObject := self.getStateObject(addr)
	if stateObject == nil || stateObject.deleted {
		stateObject, _ = self.createObject(addr)
	}
	return stateObject
}


// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
func (self *WalletTransactions) createObject(addr common.Address) (newobj, prev *stateObject) {
	prev = self.getStateObject(addr)
	newobj = newObject(self, addr, Account{})
	newobj.setNonce(0) // sets the object to dirty
	if prev == nil {
		self.journal.append(createObjectChange{account: &addr})
	} else {
		self.journal.append(resetObjectChange{prev: prev})
	}
	self.setStateObject(newobj)
	return newobj, prev
}

// Retrieve a state object given by the address. Returns nil if not found.
func (self *WalletTransactions) getStateObject(addr common.Address) (stateObject *stateObject) {
	// Prefer 'live' objects.
	if obj := self.stateObjects[addr]; obj != nil {
		if obj.deleted {
			return nil
		}
		return obj
	}

	// Load the object from the database.
	//enc, err := self.trie.TryGet(addr[:])
	enc, err := self.TryGet(addr[:])
	if len(enc) == 0 {
		self.setError(err)
		return nil
	}
	var data Account
	if err := rlp.DecodeBytes(enc, &data); err != nil {
		log.Error("Failed to decode state object", "addr", addr, "err", err)
		return nil
	}
	// Insert into the live set.
	obj := newObject(self, addr, data)
	self.setStateObject(obj)
	return obj
}

func (self *WalletTransactions) setStateObject(object *stateObject) {
	self.stateObjects[object.Address()] = object
}

// setError remembers the first non-nil error it is called with.
func (self *WalletTransactions) setError(err error) {
	if self.dbErr == nil {
		self.dbErr = err
	}
}

func (self *WalletTransactions) GetNonce(addr common.Address) uint64 {
	stateObject := self.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}

	return 0
}

// AddBalance adds amount to the account associated with addr.
func (self *WalletTransactions) AddBalance(addr common.Address, amount *big.Int) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.AddBalance(amount)
	}
}
