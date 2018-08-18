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
)

type SwarmChain struct {

	chainConfig *params.ChainConfig
	// Channel for shutting down the service
	//shutdownChan chan bool
	// Handlers
	peers           *peerSet
	txPool          map[string]*core.Transaction
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
func New(ctx *node.ServiceContext,config *node.Config) (*SwarmChain, error) {

	swc := &SwarmChain{
		//blockchain:bc,
		//chainDb:        chainDb,
		eventMux:       ctx.EventMux,
		//shutdownChan:   make(chan bool),
		etherbase:config.Etherbase,
		nodeID:config.NodeID,
	}
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
func (s *SwarmChain) SwcVersion() int                    { return 1 }

func (s *SwarmChain) EventMux() *event.TypeMux           { return s.eventMux }

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
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *SwarmChain) Stop() error {

	s.eventMux.Stop()

	//close(s.shutdownChan)

	return nil
}

