package core

import (
	"encoding/hex"
	"log"

	"github.com/boltdb/bolt"
	"math"
	"fmt"
	"os"
	."../boltqueue"
	"bytes"
	"math/big"
)

const utxoBucket = "chainstate"

var MineNow_ = false

// UTXOSet represents UTXO set
type UTXOSet struct {
	Blockchain *Blockchain
}

// FindSpendableOutputs finds and returns unspent outputs to reference in inputs
func (u UTXOSet) FindSpendableOutputs(pubkeyHash []byte, amount int,minerCheck bool,spendTxid []byte) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	accumulated := 0
	db := u.Blockchain.Db

	queueFile := fmt.Sprintf("%x_tx.db", GetAddressFromPubkeyHash(pubkeyHash))
	txPQueue, errcq := NewPQueue(queueFile)
	if errcq != nil {
		log.Panic("create queue error",errcq)
	}
	defer txPQueue.Close()
	defer os.Remove(queueFile)
	qsize, errqs := txPQueue.Size(1)
	if (errqs != nil) {
		fmt.Printf("get pending tx queue size error %s \n", errqs)
	}
	fmt.Printf("pending tx queue size %d \n", qsize)

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			txID := hex.EncodeToString(k)
			outs := DeserializeOutputs(v)
			//ignore pending tx
			fmt.Printf("UTXO txID %s \n", txID)
			if(minerCheck||(qsize==0||MineNow_ || !txPQueue.IsExist(1,k))) {
				//miner check transaction is legal or not
				if(minerCheck&&!bytes.Equal(spendTxid,k)){
					continue
				}
				for outIdx, out := range outs.Outputs {
					if out.IsLockedWithKey(pubkeyHash) && accumulated < amount {
						fmt.Printf("out.Value %d \n", out.Value)
						accumulated += out.Value
						unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)
					}
				}
			}else{

				fmt.Println("--->  exist txid: ", txID)
			}
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return accumulated, unspentOutputs
}

// FindUTXO finds UTXO for a public key hash
func (u UTXOSet) FindUTXO(pubKeyHash []byte) []TXOutput {
	var UTXOs []TXOutput
	db := u.Blockchain.Db

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			outs := DeserializeOutputs(v)

			for _, out := range outs.Outputs {
				if out.IsLockedWithKey(pubKeyHash) {
					UTXOs = append(UTXOs, out)
				}
			}
		}

		return nil
	})
	fmt.Printf("len(UTXOs) of : %d\n", len(UTXOs))
	if err != nil {
		log.Panic(err)
	}

	return UTXOs
}

// CountTransactions returns the number of transactions in the UTXO set
func (u UTXOSet) CountTransactions() int {
	db := u.Blockchain.Db
	counter := 0

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			counter++
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return counter
}

// Reindex rebuilds the UTXO set
func (u UTXOSet) Reindex() {
	db := u.Blockchain.Db
	bucketName := []byte(utxoBucket)

	err := db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(bucketName)
		if err != nil && err != bolt.ErrBucketNotFound {
			log.Panic(err)
		}

		_, err = tx.CreateBucket(bucketName)
		if err != nil {
			log.Panic(err)
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	UTXO := u.Blockchain.FindUTXO()

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)

		for txID, outs := range UTXO {
			key, err := hex.DecodeString(txID)
			if err != nil {
				log.Panic(err)
			}

			err = b.Put(key, outs.Serialize())
			if err != nil {
				log.Panic(err)
			}
		}

		return nil
	})
}

// Update updates the UTXO set with transactions from the Block
// The Block is considered to be the tip of a blockchain
func (u UTXOSet) Update(block *Block) {
	db := u.Blockchain.Db

	fmt.Printf("--->update utxo \n")
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))

		for _, tx := range block.Transactions {
			if tx.IsCoinbase() == false {
				for _, vin := range tx.Vin {
					updatedOuts := TXOutputs{}

					fmt.Printf("vin.Txid %x \n", vin.Txid)
					outs := tx.Vout

					fmt.Printf("len(outs.Outputs) %x \n", len(outs))
					for outidx, out := range outs {
						//if outidx != vin.Vout {
							fmt.Printf("outidx %d \n", outidx)
							fmt.Printf("vin.Vout %d \n", out.Value)
							updatedOuts.Outputs = append(updatedOuts.Outputs, out)
						//}
					}
					fmt.Printf("len(updatedOuts.Outputs) %x \n", len(updatedOuts.Outputs))


					if len(updatedOuts.Outputs) != 0 {
						err := b.Put(tx.ID, updatedOuts.Serialize())
						if err != nil {
							log.Panic(err)
						}
					}
					err := b.Delete(vin.Txid)
					if err != nil {
						log.Panic(err)
					}

				}
			}else{

				newOutputs := TXOutputs{}
				for _, out := range tx.Vout {
					newOutputs.Outputs = append(newOutputs.Outputs, out)
				}

				err := b.Put(tx.ID, newOutputs.Serialize())
				if err != nil {
					log.Panic(err)
				}
			}
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}


// verify transaction:timeLine UTXOAmount coinbaseTX
func (u UTXOSet) VerifyTxTimeLineAndUTXOAmount(lastBlockTime *big.Int,block *Block) bool {
	//TODO timeline check
	var coinbaseNumber = 0
	var coinbaseReward = 0
	for _, tx := range block.Transactions {

		if tx.IsCoinbase() == false {
			return u.IsUTXOAmountValid(tx)
		}else{
			coinbaseNumber = coinbaseNumber +1;
			coinbaseReward = tx.Vout[0].Value
		}
	}
	//fmt.Printf("coinbaseReward %s \n", math.Pow(0.5, math.Floor(float64(block.Height/halfRewardblockCount)))*subsidy )
	//fmt.Printf("coinbaseReward %s \n", coinbaseReward)
	//in that block reward timeperiod less than that currenteward
	if(math.Pow(0.5, math.Floor(float64(block.Height.Int64()/halfRewardblockCount)))*subsidy != float64(coinbaseReward)){
		return false
	}
	if(block.Timestamp.Cmp(lastBlockTime) <=0 ){
		fmt.Println("Timestamp.Cmp(lastBlockTime)  \n")
		return false
	}
	//fmt.Printf("coinbaseNumber %s \n", coinbaseNumber)
	if(coinbaseNumber>1){
		return false
	}

	return true
}

func (u UTXOSet) IsUTXOAmountValid(tx *Transaction) bool{
	pubKeyHash := HashPubKey(tx.Vin[0].PubKey)
	acc, _ :=
		u.FindSpendableOutputs(pubKeyHash, tx.Vout[0].Value,true,tx.Vin[0].Txid)
	//var acc = 0
	//UTXOs := UTXOSet.FindUTXO(u,pubKeyHash)
	//fmt.Printf("len UTXOs %d \n", len(UTXOs))
	//for _, out := range UTXOs {
	//	acc += out.Value
	//}
	var change = 0
	if(len(tx.Vout)>1){
		change = tx.Vout[1].Value
	}
	if(acc != ( tx.Vout[0].Value+ change)){
		fmt.Printf("tx.Vin[0].PubKey %d \n", tx.Vin[0].PubKey)
		fmt.Printf("acc %d \n", acc)
		fmt.Printf("Vout %d \n", tx.Vout[0].Value)
		fmt.Printf("change %d \n", change)
		return false
	}
	return true
}
