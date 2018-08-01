package p2pprotocol

import (
	"github.com/ethereum/go-ethereum/params"
	//"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/light"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/core/bloombits"
)

type SwarmChain struct {
	config *eth.Config

	chainConfig *params.ChainConfig
	// Channel for shutting down the service
	//shutdownChan chan bool
	// Handlers
	peers           *peerSet
	txPool          *light.TxPool
	blockchain      *light.LightChain
	protocolManager *ProtocolManager
	// DB interfaces
	//chainDb ethdb.Database // Block chain database

	ApiBackend *LesApiBackend

	eventMux       *event.TypeMux

}


// New creates a new SwarmChain object
func New(ctx *node.ServiceContext, config *Config) (*SwarmChain, error) {
	eth := &SwarmChain{
		config:         config,
		chainDb:        chainDb,
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, &config.Ethash, chainConfig, chainDb),
		shutdownChan:   make(chan bool),
		networkId:      config.NetworkId,
		gasPrice:       config.GasPrice,
		etherbase:      config.Etherbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks),
	}
	return eth, nil
}
