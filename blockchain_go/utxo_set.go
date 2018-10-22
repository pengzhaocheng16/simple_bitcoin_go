package core

import (
	"encoding/hex"
	"log"
	"github.com/boltdb/bolt"
	"math"
	"fmt"
	."../boltqueue"
	."./state"
	"math/big"
	"github.com/ethereum/go-ethereum/common"
	"bytes"
)

const utxoBucket = "chainstate"
const utxoBlockBucket = "chainstate_blockid2tx"

var MineNow_ = false

// UTXOSet represents UTXO set
type UTXOSet struct {
	Blockchain *Blockchain
}

func (u UTXOSet) FindSpentOutputs(pubkeyHash []byte, amount *big.Int,spentTxids map[string]*TXInput)(uint64, map[string][]int, map[string][]TXOutput){
	unspentOutputs := make(map[string][]int)
	unspentExtraOutputs := make(map[string][]TXOutput)
	accumulated := uint64(0)
	err := u.Blockchain.Db.View(func(tx *bolt.Tx) error {
		//b := tx.Bucket([]byte(utxoBucket))
		blockBucketName := []byte(utxoBlockBucket)
		blockb := tx.Bucket(blockBucketName)
		for txidstr,txinput := range spentTxids{
			var txid,_ = hex.DecodeString(txidstr)
			var blockHash = blockb.Get(txid)
			var block,err = u.Blockchain.GetBlock(blockHash)
			if err != nil {
				return err
			}
			updatedOuts := TXOutputs{}
			for _,tx := range block.Transactions {
				if(bytes.Equal(tx.ID,txid)){
					updatedOuts.Outputs = append(updatedOuts.Outputs, tx.Vout...)
				}
			}
			//out := b.Get(txid)
			//var outs =  DeserializeOutputs(out)
			for outIdx, out := range updatedOuts.Outputs {
				fmt.Printf("IsLockedWithKey %x \n", pubkeyHash)
				if out.IsLockedWithKey(pubkeyHash) && int64(outIdx) == txinput.Vout.Int64(){
					fmt.Printf("out.Value %d \n", out.Value)
					accumulated += uint64(out.Value)
					unspentOutputs[txidstr] = append(unspentOutputs[txidstr], outIdx)
				}else{
					unspentExtraOutputs[txidstr] = append(unspentExtraOutputs[txidstr], out)
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return accumulated, unspentOutputs,unspentExtraOutputs
}

// FindSpendableOutputs finds and returns unspent outputs to reference in inputs
func (u UTXOSet) FindSpendableOutputs(pubkeyHash []byte, amount uint64,receiverCheck bool,spentTxids map[string]*TXInput,txPQueue *PQueue) (uint64, map[string][]int, map[string][]TXOutput) {
	unspentOutputs := make(map[string][]int)
	unspentExtraOutputs := make(map[string][]TXOutput)
	accumulated := uint64(0)

	log.Println("--start  FindSpendableOutputs ")
	//queueFile := fmt.Sprintf("%x_tx.db", GetAddressFromPubkeyHash(pubkeyHash))
	var pqueue *PQueue
	var errcq error
	if(txPQueue != nil){
		pqueue = txPQueue
	}else{
		log.Println("--in  FindSpendableOutputs pqueue nil")
		queueFile := GenWalletStateDbName(u.Blockchain.NodeId)
		pqueue, errcq = NewPQueue(queueFile)
		if errcq != nil {
			log.Panic("create queue error",errcq)
		}
		//defer pqueue.Close()
		////defer os.Remove(queueFile)
	}
	defer pqueue.Close()

	qsize, errqs := pqueue.Size(1)
	if (errqs != nil) {
		fmt.Printf("get pending tx queue size error %x \n", errqs)
	}
	fmt.Printf("pending tx queue size %d \n", qsize)

	log.Println("--start  FindSpendableOutputs  u.Blockchain.Db View")
	err := u.Blockchain.Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			txID := hex.EncodeToString(k)
			outs := DeserializeOutputs(v)
			//ignore pending tx
			fmt.Printf("UTXO txID %s \n", txID)
			if(receiverCheck||(qsize==0||MineNow_ || !pqueue.IsKeyExist(1,k))) {
				//receiver check transaction is legal or not
				fmt.Printf("loop start spendTxid %x \n",spentTxids)
				if(receiverCheck && spentTxids[txID] == nil){
					fmt.Printf("ignore txid not in tx vin continue %d \n", receiverCheck)
					continue
				}
				for outIdx, out := range outs.Outputs {
					fmt.Printf("IsLockedWithKey %x \n", pubkeyHash)
					if out.IsLockedWithKey(pubkeyHash) {
						fmt.Printf("out.Value %d \n", out.Value)
						accumulated += uint64(out.Value)
						unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)
					}
				}
				if len(unspentOutputs[txID])>0{
					for _, out := range outs.Outputs {
						if !out.IsLockedWithKey(pubkeyHash) {
							unspentExtraOutputs[txID] = append(unspentExtraOutputs[txID], out)
						}
					}
				}
				if accumulated >= amount{
					break
				}
			}else{
				//spend tx in pendding outputs
				if(pqueue.IsKeyExist(1,k)){
					//witch tx spend it
					/*txidrow := pqueue.Get(1,k)
					txid := hex.EncodeToString(txidrow.Bytes())
					txMsg := pqueue.Get(3,txidrow.Bytes())
					txSerialized := txMsg.Bytes()
					txspend := DeserializeTransaction(txSerialized)
					txspend:
					for outIdx, out := range txspend.Vout {
						if(outIdx == 0){
							continue txspend
						}
						fmt.Printf("IsLockedWithKey %x \n", pubkeyHash)
						if out.IsLockedWithKey(pubkeyHash){
							fmt.Printf("out.Value %d \n", out.Value)
							accumulated += uint64(out.Value)
							unspentOutputs[txid] = append(unspentOutputs[txid], outIdx)
						}else{
							unspentExtraOutputs[txid] = append(unspentExtraOutputs[txid], out)
						}
					}*/
					fmt.Println("--->  IsExist txid: ", txID)
				}
				fmt.Println("--->  exist txid 1: ", txID)
			}
		}

		return nil
	})

	//if(txPQueue == nil) {
	//	pqueue.Close()
	//}
	log.Println("--after  FindSpendableOutputs accumulated: %d",accumulated)
	if err != nil {
		log.Panic(err)
	}

	return accumulated, unspentOutputs,unspentExtraOutputs
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
	blockBucketName := []byte(utxoBlockBucket)

	err := db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(bucketName)
		if err != nil && err != bolt.ErrBucketNotFound {
			log.Panic(err)
		}
		err = tx.DeleteBucket(blockBucketName)
		if err != nil && err != bolt.ErrBucketNotFound {
			log.Panic(err)
		}

		_, err = tx.CreateBucket(bucketName)
		if err != nil {
			log.Panic(err)
		}
		_, err = tx.CreateBucket(blockBucketName)
		if err != nil {
			log.Panic(err)
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	UTXO,UTXOBlock := u.Blockchain.FindUTXO()

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		blockb := tx.Bucket(blockBucketName)

		for txID, outs := range UTXO {
			key, err := hex.DecodeString(txID)
			if err != nil {
				log.Panic(err)
			}

			err = b.Put(key, outs.Serialize())
			if err != nil {
				log.Panic(err)
			}
			err = blockb.Put(key, UTXOBlock[txID].Bytes())
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
		blockb,err := tx.CreateBucketIfNotExists([]byte(utxoBlockBucket))
		if err != nil {
			log.Panic(err)
		}
		for _, tx := range block.Transactions {
			if tx.IsCoinbase() == false {

				updatedOuts := TXOutputs{}

				outs := tx.Vout

				fmt.Printf("--> len(outs.Outputs) %x \n", len(outs))
				for outidx, out := range outs {
					//if outidx != vin.Vout {
					fmt.Printf("tx.Vout outidx %d \n", outidx)
					fmt.Printf("tx.Vout Value %d  \n", out.Value)
					updatedOuts.Outputs = append(updatedOuts.Outputs, out)
					//}
				}
				fmt.Printf("len(updatedOuts.Outputs) %x \n", len(updatedOuts.Outputs))

				if len(updatedOuts.Outputs) != 0 {
					err := b.Put(tx.ID, updatedOuts.Serialize())
					if err != nil {
						log.Panic(err)
					}
					err = blockb.Put(tx.ID, block.Hash.Bytes())
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

				err = blockb.Put(tx.ID, block.Hash.Bytes())
				if err != nil {
					log.Panic(err)
				}
			}
		}
		//in the case spend tx in block
		for _, tx := range block.Transactions {
			if tx.IsCoinbase() == false {
				fmt.Printf("--》len(tx.Vin) %x \n", len(tx.Vin))
				for _, vin := range tx.Vin {

					fmt.Printf("vin.Txid %x \n", vin.Txid)
					err := b.Delete(vin.Txid)
					if err != nil {
						log.Panic(err)
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}


// Recover recover the UTXO set with transactions from the Block
// The Block is considered to be the start conflict block of a blockchain
func (u UTXOSet) Recover(blocks []*Block) {
	db := u.Blockchain.Db

	fmt.Printf("--->recover utxo \n")
	err := db.Update(func(tx *bolt.Tx) error {
		var err = u.RecoverOuts(tx,blocks)
		return err
	})
	if err != nil {
		log.Panic(err)
	}
}

func (u UTXOSet) RecoverOuts(tx *bolt.Tx,blocks []*Block)error{
	b := tx.Bucket([]byte(utxoBucket))
	blockb := tx.Bucket([]byte(utxoBlockBucket))
	var block *Block
	for _,block = range blocks {
		for _, tx := range block.Transactions {
			if tx.IsCoinbase() == false {

				updatedOuts := TXOutputs{}

				outs := tx.Vout

				fmt.Printf("--> len(outs.Outputs) %x \n", len(outs))
				for outidx, out := range outs {
					//if outidx != vin.Vout {
					fmt.Printf("tx.Vout outidx %d \n", outidx)
					fmt.Printf("tx.Vout Value %d  \n", out.Value)
					updatedOuts.Outputs = append(updatedOuts.Outputs, out)
					//}
				}
				fmt.Printf("len(updatedOuts.Outputs) %x \n", len(updatedOuts.Outputs))

				if len(updatedOuts.Outputs) != 0 {
					/*err := b.Put(tx.ID, updatedOuts.Serialize())*/
					err := b.Delete(tx.ID)
					if err != nil {
						log.Panic(err)
					}
					err = blockb.Delete(tx.ID)
					if err != nil {
						log.Panic(err)
					}
				}
			} else {

				/*newOutputs := TXOutputs{}
				for _, out := range tx.Vout {
					newOutputs.Outputs = append(newOutputs.Outputs, out)
				}*/
				//err := b.Put(tx.ID, updatedOuts.Serialize())
				err := b.Delete(tx.ID)
				if err != nil {
					log.Panic(err)
				}
				err = blockb.Delete(tx.ID)
				if err != nil {
					log.Panic(err)
				}
			}
		}
		//in the case spend tx in block
		for _, tx := range block.Transactions {
			if tx.IsCoinbase() == false {
				fmt.Printf("--》len(tx.Vin) %x \n", len(tx.Vin))
				for _, vin := range tx.Vin {
					fmt.Printf("vin.Txid %x \n", vin.Txid)
					blockhash := blockb.Get(vin.Txid)
					block,err := u.Blockchain.GetBlock(blockhash)
					if err != nil {
						log.Panic(err)
					}
					for _,tx := range block.Transactions{
						if(bytes.Equal(tx.ID,vin.Txid)){
							newOutputs := TXOutputs{}
							for _, out := range tx.Vout {
								newOutputs.Outputs = append(newOutputs.Outputs, out)
							}
							b.Put(tx.ID,newOutputs.Serialize())
						}
					}
					/*err := b.Delete(vin.Txid)
					if err != nil {
						log.Panic(err)
					}*/
				}
			}
		}
	}
	return nil
}

// verify transaction:timeLine UTXOAmount coinbaseTX
func (u UTXOSet) VerifyTxTimeLineAndUTXOAmount(lastBlockTime *big.Int,block *Block,txPQueue *PQueue) (bool,int) {
	//TODO timeline check
	var coinbaseNumber = uint64(0)
	var coinbaseReward = uint64(0)
	var result = false;
	queueFile := GenWalletStateDbName(u.Blockchain.NodeId)
	txPQueue, errcq := NewPQueue(queueFile)
	if errcq != nil{
		log.Panic(errcq)
	}

	for k, tx := range block.Transactions {

		if tx.IsCoinbase() == false {
			//if vin txid in transaction has used return false
			for _,Vin := range tx.Vin {
				vintx := txPQueue.IsKeyExist(4,Vin.Txid)
				if (vintx){
					//delete outdated vin txid in database
					for _,tx1 := range block.Transactions[0:k]{
						for _,in := range tx1.Vin{
							//delete vin tx id
							txPQueue.DeleteMsg(4,in.Txid)
						}
					}
					return false,8;
				}
			}
			txPQueue.Close()
			fmt.Println("--bf IsUTXOAmountValid  \n")
			result = VerifyTx(*tx,u.Blockchain)
			if(!result){
				return result,9
			}
			//result = u.IsUTXOAmountValid(tx,nil)
			//fmt.Printf("--af IsUTXOAmountValid  result %s \n",result)
			queueFile := GenWalletStateDbName(u.Blockchain.NodeId)
			var errcq error
			txPQueue, errcq = NewPQueue(queueFile)
			//defer txPQueue.Close()
			if errcq != nil {
				log.Panic("create queue error", errcq)
			}
			if(!result){
				fmt.Println("--bf result check false  \n")
				//delete outdated vin txid in database
				for _,tx1 := range block.Transactions[0:k]{
					for _,in := range tx1.Vin{
						//delete vin tx id
						txPQueue.DeleteMsg(4,in.Txid)
					}
				}
				return result,10
			}else{
				fmt.Println("--bf result check true \n")
				//txid has used put it in database
				for _,Vin := range tx.Vin{
					txPQueue.SetMsg(4,Vin.Txid,Vin.Txid)
				}
			}
			txPQueue.Close()
		}else{
			coinbaseNumber = coinbaseNumber +1
			coinbaseReward = tx.Vout[0].Value
		}
	}
	//txPQueue.Close()
	//fmt.Printf("coinbaseReward %s \n", math.Pow(0.5, math.Floor(float64(block.Height/halfRewardblockCount)))*subsidy )
	//fmt.Printf("coinbaseReward %s \n", coinbaseReward)
	//in that block reward timeperiod less than that currenteward
	if(math.Pow(0.5, math.Floor(float64(block.Height.Int64()/halfRewardblockCount)))*subsidy != float64(coinbaseReward)){
		return false,11
	}
	if(block.Timestamp.Cmp(lastBlockTime) <=0 ){
		fmt.Println("Timestamp.Cmp(lastBlockTime)  \n")
		return false,12
	}
	//fmt.Printf("coinbaseNumber %s \n", coinbaseNumber)
	if(coinbaseNumber>1){
		return false,13
	}

	return true,0
}

func (u UTXOSet) IsUTXOAmountValid(tx *Transaction,pqueue *PQueue) bool{
	pubKeyHash := HashPubKey(tx.Vin[0].PubKey)
	var spenttxids = map[string]*TXInput{}
	for _,txin := range tx.Vin{
		spenttxids[hex.EncodeToString(txin.Txid)] = &txin
	}
	/*acc, _, extraOutputs :=
		u.FindSpendableOutputs(pubKeyHash, big.NewInt(int64(tx.Vout[0].Value)),true,spenttxids,pqueue)
	*/
	acc, _, extraOutputs :=
		u.FindSpentOutputs(pubKeyHash, big.NewInt(int64(tx.Vout[0].Value)),spenttxids)
	///var acc = 0
	//UTXOs := UTXOSet.FindUTXO(u,pubKeyHash)
	//fmt.Printf("len UTXOs %d \n", len(UTXOs))
	//for _, out := range UTXOs {
	//	acc += out.Value
	//}
	var change = uint64(0)
	if(len(tx.Vout)>1){
		for idx,out := range tx.Vout{
			if(idx>0){
				change = change + out.Value
			}
		}
	}
	fmt.Printf("len(extraOutputs) %d \n", len(extraOutputs))
	for _,outs := range extraOutputs {
		for _,exout := range outs{
			acc = acc + exout.Value
		}
	}
	if(acc != ( tx.Vout[0].Value+ change)){
		fmt.Printf("tx.Vin[0].PubKey %x \n", pubKeyHash)
		fmt.Printf("acc %d \n", acc)
		fmt.Printf("Vout %d \n", tx.Vout[0].Value)
		fmt.Printf("change %d \n", change)
		return false
	}
	return true
}

func (u *UTXOSet)GetTxInOuts(from common.Address,to common.Address,amount *big.Int,nodeID string)([]TXInput,[]TXOutput,error){
	defer u.Blockchain.Db.Close()
	var pubKeyHash []byte = from.Bytes()

	/*// Convert the amount to honey.
	honey, err := btcutil.NewAmount(subsidy)
	if err != nil {
		context := "Failed to convert amount"
		log.Println(errors.New(err.Error()+context))
		return nil,nil,errors.New(err.Error()+context)
	}*/
	var honey = amount.Int64()
	acc, validOutputs,extraOutputs := u.FindSpendableOutputs(pubKeyHash, uint64(honey),false,nil,nil)

	if acc < uint64(honey) {
		return nil,nil,ErrNotEnoughFunds
	}

	var inputs []TXInput
	var outputs []TXOutput
	// Build a list of inputs
	for txid, outs := range validOutputs {
		txID, err := hex.DecodeString(txid)
		if err != nil {
			log.Panic(err)
		}
		for _, out := range outs {
			//input := TXInput{txID, out, nil, wallet.PublicKey}
			input := TXInput{txID, big.NewInt(int64(out)), nil, nil}
			inputs = append(inputs, input)
		}
	}
	// Build a list of outputs
	//from := fmt.Sprintf("%s", GetAddressFromPubkeyHash(pubKeyHash))
	fromstr := fmt.Sprintf("%s", from)
	tostr := fmt.Sprintf("%s", to)
	outputs = append(outputs, *NewTXOutput(uint64(honey), tostr))
	if acc > uint64(honey) {
		outputs = append(outputs, *NewTXOutput(uint64(acc-uint64(honey)), fromstr)) // a change
	}
	for _,txouts := range extraOutputs{
		outputs = append(outputs,txouts...)
	}
	return inputs,outputs,nil
}