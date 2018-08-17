
package main

import (
	"fmt"
	"../rpc"
	"../blockchain_go"
)

func main() {

	client, err := rpc.Dial("http://localhost:8545")
	if err != nil {
		fmt.Println("rpc.Dial err", err)
		return
	}

	var  block *core.Block
	err = client.Call(&block, "CurrentBlock")
	fmt.Println("block ", block)

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
}
