package main

import (
	"fmt"
	"log"
	"../blockchain_go"
	"github.com/boltdb/bolt"
	"bytes"
)

//定义一个person结构，类似于在PHP定义了一个person的class
type person struct {
	name string //默认零值为空字符串
	age  int    //默认零值为0
}

func main() {
	//如何传递指针
	a := &person{ //变量初始化时，加&取地址
		name: "GO",
		age:  8} //注意，如果没有逗号，则}不能另起新行，否则会报错
	//当传地址的时候，想操作属性时，Go语言可以不需要加*，直接操作
	a.age = 9
	fmt.Println("我在A前面输出", a)
	A(a)
	fmt.Println("我在A后面输出", a) //很显然,A里面的赋值并没有改变a的值，证明结构是值类型，传值是值拷贝

	bc := core.NewBlockchain("192.168.43.134:2001")
	defer bc.Db.Close()
	UTXOSet := core.UTXOSet{bc}
	UTXOSet.Reindex()

	//update(bc,&UTXOSet)
}

//结构也是值类型，传值的时候也是值拷贝
func A(per *person) { //此时为指针类型
	per = &person{ //变量初始化时，加&取地址
		name: "PHP",
		age:  8}
	//per.name = "PHP"
	fmt.Println("我在A里面输出", per)
}

const utxoBucket = "chainstate"
const blocksBucket = "blocks"
func  update(bc *core.Blockchain,utxo *core.UTXOSet) {
	bucketName := []byte(utxoBucket)
	err := bc.Db.Update(func(tx *bolt.Tx) error {
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
	bc.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		bu := tx.Bucket([]byte(utxoBucket))
		g := b.Get([]byte("g"))

		encodedBlock := b.Get(g)

		block := core.DeserializeBlock(encodedBlock)
		//fmt.Printf("-->block %x \n", block)

		for _, tx := range block.Transactions {
			newOutputs := core.TXOutputs{}
			for _, out := range tx.Vout {
				newOutputs.Outputs = append(newOutputs.Outputs, out)
			}

			fmt.Printf("tx.ID %x \n", tx.ID)
			err := bu.Put(tx.ID, newOutputs.Serialize())
			if err != nil {
				log.Panic(err)
			}
		}

		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			encodedBlock := v
			//tip is genesis block need to skip!!!
			if(len(encodedBlock) == 32||bytes.Equal(g,k)){
				continue
			}
			block := core.DeserializeBlock(encodedBlock)

			//bc.Db.Close()
			//bc := core.NewBlockchain("192.168.43.134:2001")
			//defer bc.Db.Close()
			//utxo := core.UTXOSet{bc}
			//utxo.Update(block)

			for _, tx := range block.Transactions {
				if tx.IsCoinbase() == false {
					updatedOuts := core.TXOutputs{}

					outs := tx.Vout

					fmt.Printf("-->len(outs.Outputs) %x \n", len(outs))
					for outidx, out := range outs {
						//if outidx != vin.Vout {
						fmt.Printf("tx.Vout outidx %d \n", outidx)
						fmt.Printf("tx.Vout Value %d  \n", out.Value)
						updatedOuts.Outputs = append(updatedOuts.Outputs, out)
						//}
					}
					fmt.Printf("len(updatedOuts.Outputs) %x \n", len(updatedOuts.Outputs))

					if len(updatedOuts.Outputs) != 0 {
						err := bu.Put(tx.ID, updatedOuts.Serialize())
						if err != nil {
							log.Panic(err)
						}
					}
				}else{

					newOutputs := core.TXOutputs{}
					for _, out := range tx.Vout {
						newOutputs.Outputs = append(newOutputs.Outputs, out)
					}

					fmt.Printf("tx.ID %x \n", tx.ID)
					err := bu.Put(tx.ID, newOutputs.Serialize())
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
						o := bu.Get(vin.Txid)
						out := core.DeserializeOutputs(o)
						fmt.Printf("len(out) %d \n", len(out.Outputs))

						err := bu.Delete(vin.Txid)
						o1 := bu.Get(vin.Txid)
						if(o1!=nil){
							out1 := core.DeserializeOutputs(o1)
							fmt.Printf("len(out1) %d \n", len(out1.Outputs))
						}else{
							fmt.Printf("len(out1) %d \n", 0)
						}
						if err != nil {
							log.Panic(err)
						}
					}
				}
			}

		}
		return nil
	})

}