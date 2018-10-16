package p2pprotocol

import (
	"context"
	"../blockchain_go"
	//"github.com/ethereum/go-ethereum/rpc"

	"../rpc"
	"fmt"
	"math/big"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/event"
	"encoding/hex"
)

//import "github.com/ethereum/go-ethereum/eth/gasprice"

// SWCAPIBackend implements swcapi.Backend for full nodes
type SwcAPIBackend struct {
	swc *SwarmChain
	//gpo *gasprice.Oracle
}

func (b *SwcAPIBackend) ChainConfig() *params.ChainConfig {
	return b.swc.chainConfig
}

func (b *SwcAPIBackend) CurrentBlock() *core.Block {
	bc := core.NewBlockchain(b.swc.nodeID)
	defer bc.Db.Close()
	return bc.CurrentBlock()
}
/*
func (b *SwcAPIBackend) SetHead(number uint64) {
	b.swc.protocolManager.downloader.Cancel()
	b.swc.blockchain.SetHead(number)
}
func (b *SwcAPIBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		block := b.swc.miner.PendingBlock()
		return block.Header(), nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.swc.blockchain.CurrentBlock().Header(), nil
	}
	return b.swc.blockchain.GetHeaderByNumber(uint64(blockNr)), nil
}
*/

func (b *SwcAPIBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*core.Block, error) {
	// Pending block is only known by the miner
	//if blockNr == rpc.PendingBlockNumber {
	//	block := b.swc.miner.PendingBlock()
	//	return block, nil
	//}
	fmt.Println(" blockNr：", blockNr)
	//fmt.Println(" b.swc：", b.swc)
	//fmt.Println(" b.swc.blockchain：", b.swc.blockchain)
	// Otherwise resolve and return the block
	bc := core.NewBlockchain(b.swc.nodeID)
	b.swc.blockchain = bc
	defer bc.Db.Close()
	if blockNr == rpc.LatestBlockNumber {
		return b.swc.blockchain.CurrentBlock(), nil
	}
	return b.swc.blockchain.GetBlockByNumber(uint64(blockNr)), nil
}

func (b *SwcAPIBackend) GetBalance(ctx context.Context, address common.Address) (int64, error) {
	var balance *big.Int

	bc := core.NewBlockchain(b.swc.nodeID)
	b.swc.blockchain = bc
	balance = b.swc.blockchain.GetBalance(address,b.swc.nodeID)
	println("---",balance.Uint64())
	return balance.Int64(),nil
}

func (b *SwcAPIBackend)GetTxInOuts(ctx context.Context,from common.Address,to common.Address,amount *big.Int)([]core.TXInput,[]core.TXOutput,error){

	bc := core.NewBlockchain(b.swc.nodeID)
	utxo := core.UTXOSet{bc}
	inputs,outputs,err := utxo.GetTxInOuts(from,to,amount,"")

	//prevTXs := make(map[string]core.Transaction)

	for _, vin := range inputs {
		prevTX, err := bc.FindTransaction(vin.Txid)
		vin.Signature = nil
		vin.PubKey = prevTX.Vout[vin.Vout.Int64()].PubKeyHash
		if err != nil {
			return nil,nil,err
		}
		//prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}

	return inputs,outputs,err
}
	/*
	func (b *SwcAPIBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
		// Pending state is only known by the miner
		if blockNr == rpc.PendingBlockNumber {
			block, state := b.swc.miner.Pending()
			return state, block.Header(), nil
		}
		// Otherwise resolve the block number and return its state
		header, err := b.HeaderByNumber(ctx, blockNr)
		if header == nil || err != nil {
			return nil, nil, err
		}
		stateDb, err := b.swc.BlockChain().StateAt(header.Root)
		return stateDb, header, err
	}

	func (b *SwcAPIBackend) GetBlock(ctx context.Context, hash common.Hash) (*types.Block, error) {
		return b.swc.blockchain.GetBlockByHash(hash), nil
	}

	func (b *SwcAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
		if number := rawdb.ReadHeaderNumber(b.swc.chainDb, hash); number != nil {
			return rawdb.ReadReceipts(b.swc.chainDb, hash, *number), nil
		}
		return nil, nil
	}

	func (b *SwcAPIBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
		number := rawdb.ReadHeaderNumber(b.swc.chainDb, hash)
		if number == nil {
			return nil, nil
		}
		receipts := rawdb.ReadReceipts(b.swc.chainDb, hash, *number)
		if receipts == nil {
			return nil, nil
		}
		logs := make([][]*types.Log, len(receipts))
		for i, receipt := range receipts {
			logs[i] = receipt.Logs
		}
		return logs, nil
	}

	func (b *SwcAPIBackend) GetTd(blockHash common.Hash) *big.Int {
		return b.swc.blockchain.GetTdByHash(blockHash)
	}

	func (b *SwcAPIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
		state.SetBalance(msg.From(), math.MaxBig256)
		vmError := func() error { return nil }

		context := core.NewEVMContext(msg, header, b.swc.BlockChain(), nil)
		return vm.NewEVM(context, state, b.swc.chainConfig, vmCfg), vmError, nil
	}

	func (b *SwcAPIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
		return b.swc.BlockChain().SubscribeRemovedLogsEvent(ch)
	}

	func (b *SwcAPIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
		return b.swc.BlockChain().SubscribeChainEvent(ch)
	}

	func (b *SwcAPIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
		return b.swc.BlockChain().SubscribeChainHeadEvent(ch)
	}

	func (b *SwcAPIBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
		return b.swc.BlockChain().SubscribeChainSideEvent(ch)
	}

	func (b *SwcAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
		return b.swc.BlockChain().SubscribeLogsEvent(ch)
	}
*/
	func (b *SwcAPIBackend) SendTx(ctx context.Context, signedTx *core.Transaction) error {
		log.Info("===Manager.Peers.Peers len %d ","info",len(Manager.Peers.Peers))
		signedTx.InitFrom(b.swc.txPool.Signer)
		// TODO pool lock mangement
		Manager.Mu.Lock()
		defer Manager.Mu.Unlock()
		/*for _, p := range Manager.Peers.Peers {
			SendTx(p, p.Rw, signedTx)
		}*/

		Manager.TxMempool[hex.EncodeToString(signedTx.ID)] = signedTx

		//set nonce to statedb
		//statedb.Finalise(true)
		var pendingState = Manager.txPool.State()
		// Make sure the transaction is signed properly
		from, err := core.Sender(Manager.txPool.Signer, signedTx)
		if err != nil {
			log.Error("error",core.ErrInvalidSender)
		}
		pendingState.SetNonce(from,signedTx.Nonce())
		//pendingState.StateDB.Finalise(true)
		err = b.swc.txPool.AddLocal(signedTx)
		fmt.Printf("===AddLocal %s \n", "error",err)

		return nil
	}

	func (b *SwcAPIBackend) GetPoolTransactions() (core.Transactions, error) {
		pending, err := b.swc.txPool.Pending()
		if err != nil {
			return nil, err
		}
		var txs core.Transactions
		for _, batch := range pending {
			txs = append(txs, batch...)
		}
		return txs, nil
	}

	func (b *SwcAPIBackend) GetPoolTransaction(hash common.Hash) *core.Transaction {
		return b.swc.txPool.Get(hash)
	}

	func (b *SwcAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
		return b.swc.txPool.State().GetNonce(addr), nil
		//return core.GetPoolNonce(b.swc.nodeID,addr.String())
	}

	func (b *SwcAPIBackend) GetNodeId() string{
		return b.swc.nodeID
	}

	func (b *SwcAPIBackend) Stats() (pending int, queued int) {
		return b.swc.txPool.Stats()
	}

	func (b *SwcAPIBackend) TxPoolContent() (map[common.Address]core.Transactions, map[common.Address]core.Transactions) {
		return b.swc.TxPool().Content()
	}

	func (b *SwcAPIBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
		return b.swc.TxPool().SubscribeNewTxsEvent(ch)
	}
/*
	func (b *SwcAPIBackend) Downloader() *downloader.Downloader {
		return b.swc.Downloader()
	}*/

func (b *SwcAPIBackend) ProtocolVersion() int {
	return b.swc.SwcVersion()
}
/*
func (b *SwcAPIBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *SwcAPIBackend) ChainDb() ethdb.Database {
	return b.swc.ChainDb()
}*/

/*
func (b *SwcAPIBackend) EventMux() *event.TypeMux {
	return b.swc.EventMux()
}*/