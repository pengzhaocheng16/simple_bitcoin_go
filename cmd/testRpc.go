
package main

import (
	"fmt"
	"../rpc"
	"math/big"
	"github.com/ethereum/go-ethereum/common/hexutil"
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

	err = client.Call(&blockNumber, "swc_blockNumber")
	err = client.Call(&swc_coinbase, "swc_coinbase")
	err = client.Call(&clientversion, "web3_clientVersion")
	var bigint = new(big.Int).SetInt64(0)
	var bigNumber = (*hexutil.Big)(bigint)
	err = client.Call(&block, "swc_getBlockByNumber",bigNumber,false)

	var  balance = int64(0)

	err = client.Call(&balance, "swc_getBalance","1NWUWL17WtxzSMVWhGm8UD7Y45ikFUHZCx")

	fmt.Println("swc_blockNumber ", blockNumber)
	fmt.Println("swc_coinbase ", swc_coinbase)
	fmt.Println("web3_clientversion ", clientversion)
	fmt.Println("swc_getBlockByNumber ", block)
	fmt.Println("swc_getBalance ",balance )

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
