package core

import (
	"github.com/boltdb/bolt"
	"fmt"
	"log"
	"encoding/binary"
)

const walletTransactionsBucket = "wallettransactions"
const walletTransactionsCountBucket = "wallettransactionsCount"

type WalletTransactions struct {
	DB *bolt.DB
}

func (uts *WalletTransactions) InitDB(chainId,address string) error {
	dbFile := GenWalletStateDbName(chainId)
	fmt.Printf("wallet transaction file %s\n",dbFile)
	if dbExists(dbFile) {
		fmt.Println("wallet transaction file already exists.")
		//os.Exit(1)
	}

	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	uts.DB = db;

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