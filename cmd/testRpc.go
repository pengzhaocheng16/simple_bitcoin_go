
package main

import (
	"fmt"
	"../rpc"
	"../internal/swcapi"
	"math/big"
	"../blockchain_go"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common"
)

func main() {

	client, err := rpc.Dial("http://localhost:8545")
	if err != nil {
		fmt.Println("rpc.Dial err", err)
		return
	}

	var  blockNumber uint64
	var  swc_coinbase string
	var  clientversion string
	var  block map[string]interface{}
	var  txhash common.Hash
	var  txhash1 common.Hash

	err = client.Call(&blockNumber, "eth_blockNumber")
	err = client.Call(&swc_coinbase, "eth_coinbase")
	err = client.Call(&clientversion, "web3_clientVersion")
	var bigint = new(big.Int).SetInt64(0)
	var bigNumber = (*hexutil.Big)(bigint)
	err = client.Call(&block, "eth_getBlockByNumber",bigNumber,false)

	var  balance = int64(0)

	var bigint1 = new(big.Int).SetInt64(0)
	var bigNumber1 = (*hexutil.Big)(bigint1)
	err = client.Call(&balance, "eth_getBalance","1Q1oECL9rvC642THhNB6QZMqU55fDieXDK",bigNumber1)

	sendTx := new(swcapi.SendTxArgs)
	sendTx1 := new(swcapi.SendTxArgs)
	var from = core.Base58ToCommonAddress([]byte("1Mfi82c8d54iD28DPQ98SG4bPkmUSeWxw5"))
	//var to = core.Base58ToCommonAddress([]byte("1Q1oECL9rvC642THhNB6QZMqU55fDieXDK"))
	var to = core.Base58ToCommonAddress([]byte("1G7EmF7Umd96FLMKh3PhqZCi3bfMzqC4tH"))
	var from1 = core.Base58ToCommonAddress([]byte("1Mfi82c8d54iD28DPQ98SG4bPkmUSeWxw5"))
	var to1 = core.Base58ToCommonAddress([]byte("1G7EmF7Umd96FLMKh3PhqZCi3bfMzqC4tH"))


	var nonce = hexutil.Uint64(1)
	var bigi = new(big.Int).SetInt64(10)
	var value = (*hexutil.Big)(bigi)
	var data = hexutil.Bytes{}
	sendTx.From = from
	sendTx.To = &to
	sendTx.Nonce = &nonce
	sendTx.Value = value
	sendTx.Data = &data

	sendTx1.From = from1
	sendTx1.To = &to1
	sendTx1.Nonce = &nonce
	sendTx1.Value = value
	sendTx1.Data = &data

	err = client.Call(&txhash, "personal_sendTransaction",sendTx,"")
	err = client.Call(&txhash1, "personal_sendTransaction",sendTx1,"")

	fmt.Println("eth_blockNumber ", blockNumber)
	fmt.Println("eth_coinbase ", swc_coinbase)
	fmt.Println("web3_clientversion ", clientversion)
	fmt.Println("eth_getBlockByNumber ", block)
	fmt.Println("eth_getBalance ",balance )
	fmt.Println("personal_sendTransaction ",txhash )
	fmt.Println("personal_sendTransaction1 ",txhash1 )

	/*var account[]string
	err = client.Call(&account, "eth_accounts")
	var result string
	//var result hexutil.Big
	err = client.Call(&result, "eth_getBalance", account[0], "latest")
	//err = ec.c.CallContext(ctx, &result, "eth_getBalance", account, "latest")
*/
	if err != nil {
		fmt.Println("client.Call err", err)
		return
	}

	//fmt.Printf("account[0]: %s\nbalance[0]: %s\n", account[0], result)
	//fmt.Printf("accounts: %s\n", account[0])

	/*
	curl --header "Content-Type:application/json"  --data {\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"0x407\", \"latest\"],\"id\":1} http://localhost:8545
	 curl -l -H "Content-Type:application/json" -H "Accept:application/json" -X POST -d {\"jsonrpc\":\"2.0\",\"method\":\"swc_coinbase\",\"id\":1} http://localhost:8545

	*/
}
