package p2pprotocol

import (
	"sync"
	"github.com/ethereum/go-ethereum/params"
	//"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"../node"
	"../blockchain_go"
	"../internal/swcapi"
	"../rpc"
	//"github.com/ethereum/go-ethereum/eth/downloader"
	//"github.com/ethereum/go-ethereum/eth/filters"
	"../p2p"
	"github.com/ethereum/go-ethereum/common"
	"fmt"
	"math/big"
)

type SwarmChain struct {

	chainConfig *params.ChainConfig
	// Channel for shutting down the service
	//shutdownChan chan bool
	// Handlers
	peers           *peerSet
	//txMemPool          map[string]*core.Transaction
	txPool         *core.TxPool
	blockchain      *core.Blockchain
	protocolManager *ProtocolManager
	// DB interfaces
	//chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux

	ApiBackend *SwcAPIBackend

	etherbase common.Address

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)
	nodeID string
}

// New creates a new SwarmChain object
func New(ctx *node.ServiceContext,config *node.Config,bc *core.Blockchain) (*SwarmChain, error) {

	swc := &SwarmChain{
		//blockchain:bc,
		//chainDb:        chainDb,
		protocolManager:Manager,
		eventMux:       ctx.EventMux,
		//shutdownChan:   make(chan bool),
		etherbase:config.Etherbase,
		nodeID:config.NodeID,
	}

	var TxPoolConfig = core.DefaultTxPoolConfig
	chainConfig:= &params.ChainConfig{
		ChainID:big.NewInt(1),
	}//gen.Config
	//bc := core.NewBlockchain(config.NodeID)
	//defer bc.Db.Close()

	swc.txPool = core.NewTxPool(TxPoolConfig, chainConfig,bc)
	Manager.txPool = swc.txPool

	swc.ApiBackend = &SwcAPIBackend{swc}

	return swc, nil
}


// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *SwarmChain) APIs() []rpc.API {
	apis := swcapi.GetAPIs(s.ApiBackend)

	// Append any APIs exposed explicitly by the consensus engine
	//apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "swc",
			Version:   "1.0",
			Service:   NewPublicEthereumAPI(s),
			Public:    true,
		},/* {
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicMinerAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.APIBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s.chainConfig, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},*/
	}...)
}
/*
func (s *SwarmChain) AccountManager() *accounts.Manager  { return s.accountManager }*/
func (s *SwarmChain) BlockChain() *core.Blockchain       { return s.blockchain }
func (s *SwarmChain) TxPool() *core.TxPool               { return s.txPool }
func (s *SwarmChain) EventMux() *event.TypeMux           { return s.eventMux }

func (s *SwarmChain) IsListening() bool                  { return true } // Always listening
func (s *SwarmChain) SwcVersion() int                    { return 1 }

func (s *SwarmChain) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}

	return common.Address{}, fmt.Errorf("etherbase must be explicitly specified")
}

// SetEtherbase sets the mining reward address.
func (s *SwarmChain) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.lock.Unlock()

	//s.miner.SetEtherbase(etherbase)
}

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
/*func (s *SwarmChain) Protocols() []p2p.Protocol {
	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
}*/


// Start implements node.Service, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *SwarmChain) Start(srvr *p2p.Server) error {
	/*// Start the bloom bits servicing goroutines
	s.startBloomHandlers()

	// Start the RPC service
	s.netRPCService = ethapi.NewPublicNetAPI(srvr, s.NetVersion())
*/
	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	/*if s.config.LightServ > 0 {
		if s.config.LightPeers >= srvr.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, srvr.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}*/

	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	/*if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}*/
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *SwarmChain) Stop() error {

	s.eventMux.Stop()

	//s.bloomIndexer.Close()
	//s.blockchain.Stop()
	s.protocolManager.Stop()
	/*if s.lesServer != nil {
		s.lesServer.Stop()
	}*/
	s.txPool.Stop()
	//s.miner.Stop()
	s.eventMux.Stop()

	//s.chainDb.Close()
	//close(s.shutdownChan)


	return nil
}

