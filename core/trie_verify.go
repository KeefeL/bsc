package core

import (
	"fmt"
	"math/rand"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

const (
	verifiedCacheSize = 256
	maxForkHeight     = 11
	resendInterval    = 2 * time.Second
	// defaultPeerNumber is default number of verify peers
	defaultPeerNumber = 3
	// tryAllPeersTime is the time that a block has not been verified and then try all the valid verify peers.
	tryAllPeersTime = 15 * time.Second
)

type VerifyManager struct {
	bc                   *BlockChain
	tasks                map[common.Hash]*VerifyTask
	peers                VerifyPeers
	verifiedCache        *lru.Cache
	allowUntrustedVerify bool
	newTaskCh            chan *types.Header
	verifyCh             chan common.Hash
	messageCh            chan VerifyMessage
	exitCh               chan struct{}
}

func NewVerifyManager(blockchain *BlockChain, allowUntrustedVerify bool) *VerifyManager {
	verifiedCache, _ := lru.New(verifiedCacheSize)
	vm := &VerifyManager{
		bc:                   blockchain,
		tasks:                make(map[common.Hash]*VerifyTask),
		verifiedCache:        verifiedCache,
		newTaskCh:            make(chan *types.Header),
		verifyCh:             make(chan common.Hash),
		messageCh:            make(chan VerifyMessage),
		exitCh:               make(chan struct{}),
		allowUntrustedVerify: allowUntrustedVerify,
	}
	return vm
}

func (vm *VerifyManager) verifyManagerLoop() {
	// read disk store to initial verified cache
	// load unverified blocks in a normalized chain and start a batch of verify task
	header := vm.bc.CurrentHeader()
	// Start verify task from H to H-11 if need.
	vm.NewBlockVerifyTask(header)
	prune := time.NewTicker(time.Second)
	defer prune.Stop()
	for {
		select {
		case h := <-vm.newTaskCh:
			vm.NewBlockVerifyTask(h)
		case hash := <-vm.verifyCh:
			vm.cacheBlockVerified(hash)
			rawdb.MarkTrustBlock(vm.bc.db, hash)
			if task, ok := vm.tasks[hash]; ok {
				delete(vm.tasks, hash)
				close(task.terminalCh)
			}
		case <-prune.C:
			for hash, task := range vm.tasks {
				if vm.bc.CurrentHeader().Number.Uint64()-task.blockHeader.Number.Uint64() > 15 {
					delete(vm.tasks, hash)
					close(task.terminalCh)
				}
			}
		case message := <-vm.messageCh:
			if vt, ok := vm.tasks[message.verifyResult.BlockHash]; ok {
				vt.messageCh <- message
			}
		case <-vm.exitCh:
			return
		}
	}
}

func (vm *VerifyManager) Stop() {
	// stop all the tasks
	for _, task := range vm.tasks {
		close(task.terminalCh)
	}
	close(vm.exitCh)
}

func (vm *VerifyManager) NewBlockVerifyTask(header *types.Header) {
	for i := 0; header != nil && i <= maxForkHeight; i++ {
		func(hash common.Hash){
			// if verified cache record that this block has been verified, skip.
			if _, ok := vm.verifiedCache.Get(hash); ok {
				return
			}
			// if there already has a verify task for this block, skip.
			if _, ok := vm.tasks[hash]; ok {
				return
			}
			// if verified storage record that this block has been verified, skip.
			if rawdb.IsTrustBlock(vm.bc.db, hash) {
				vm.cacheBlockVerified(hash)
				return
			}
			diffLayer := vm.bc.GetTrustedDiffLayer(hash)
			// if this block has no diff, there is no need to verify it.
			var err error
			if diffLayer == nil {
				if diffLayer, err = vm.bc.GenerateDiffLayer(hash); err != nil {
					log.Error("failed to get diff layer", "block", hash, "number", header.Number, "error", err)
					return
				}
			}
			diffHash, err := GetTrustedDiffHash(diffLayer)
			if err != nil {
				log.Error("failed to get diff hash", "block", hash, "number", header.Number, "error", err)
				return
			}
			verifyTask := NewVerifyTask(diffHash, header, vm.peers, vm.bc.db, vm.verifyCh, vm.allowUntrustedVerify)
			vm.tasks[hash] = verifyTask
		}(header.Hash())
		header = vm.bc.GetHeaderByHash(header.ParentHash)
	}
}

func (vm *VerifyManager) cacheBlockVerified(hash common.Hash) {
	if vm.verifiedCache.Len() >= verifiedCacheSize {
		vm.verifiedCache.RemoveOldest()
	}
	vm.verifiedCache.Add(hash, true)
}

// AncestorVerified function check block has been verified or it's a empty block.
func (vm *VerifyManager) AncestorVerified(header *types.Header) bool {
	// find header of H-11 block.
	header = vm.bc.GetHeaderByNumber(header.Number.Uint64() - maxForkHeight)
	// If start from genesis block, there has not a H-11 block.
	if header == nil {
		return true
	}
	// check whether H-11 block is a empty block.
	if header.TxHash == types.EmptyRootHash {
		parent := vm.bc.GetHeaderByHash(header.ParentHash)
		if header.Root == parent.Root {
			return true
		}
	}
	hash := header.Hash()
	if _, ok := vm.verifiedCache.Get(hash); ok {
		return true
	}
	return rawdb.IsTrustBlock(vm.bc.db, hash)
}

func (vm *VerifyManager) HandleRootResponse(vr *VerifyResult, pid string) error {
	vm.messageCh <- VerifyMessage{verifyResult: vr, peerId: pid}
	return nil
}

type VerifyResult struct {
	Status      types.VerifyStatus
	BlockNumber uint64
	BlockHash   common.Hash
	Root        common.Hash
}

type VerifyMessage struct {
	verifyResult *VerifyResult
	peerId       string
}

type VerifyTask struct {
	diffhash             common.Hash
	blockHeader          *types.Header
	candidatePeers       VerifyPeers
	BadPeers             map[string]struct{}
	startAt              time.Time
	db                   ethdb.Database
	allowUntrustedVerify bool

	messageCh  chan VerifyMessage
	terminalCh chan struct{}
}

func NewVerifyTask(diffhash common.Hash, header *types.Header, peers VerifyPeers, db ethdb.Database, verifyCh chan common.Hash, allowUntrustedVerify bool) *VerifyTask {
	vt := &VerifyTask{
		diffhash:             diffhash,
		blockHeader:          header,
		candidatePeers:       peers,
		BadPeers:             make(map[string]struct{}),
		db:                   db,
		allowUntrustedVerify: allowUntrustedVerify,
		messageCh:            make(chan VerifyMessage),
		terminalCh:           make(chan struct{}),
	}
	go vt.Start(verifyCh)
	return vt
}

func (vt *VerifyTask) Start(verifyCh chan common.Hash) {
	vt.startAt = time.Now()

	vt.selectPeersToVerify(defaultPeerNumber)
	resend := time.NewTicker(resendInterval)
	defer resend.Stop()
	for {
		select {
		case msg := <-vt.messageCh:
			switch msg.verifyResult.Status {
			case types.StatusFullVerified:
				vt.compareRootHashAndWrite(msg, verifyCh)
			case types.StatusUntrustedVerified:
				log.Warn("block %s , num= %s is untrusted verified", msg.verifyResult.BlockHash, msg.verifyResult.BlockNumber)
				if vt.allowUntrustedVerify {
					vt.compareRootHashAndWrite(msg, verifyCh)
				}
			case types.StatusDiffHashMismatch, types.StatusImpossibleFork, types.StatusUnexpectedError:
				vt.BadPeers[msg.peerId] = struct{}{}
				log.Debug("peer %s is not available: %s", msg.peerId, msg.verifyResult.Status.Msg)
			case types.StatusBlockTooNew, types.StatusBlockNewer, types.StatusPossibleFork:
				log.Info("return msg from peer %s for block %s is %s", msg.peerId, msg.verifyResult.BlockHash, msg.verifyResult.Status.Msg)
			}
		case <-resend.C:
			// if a task has run over 15s, try all the vaild peers to verify.
			if time.Since(vt.startAt) < tryAllPeersTime {
				vt.selectPeersToVerify(1)
			} else {
				vt.selectPeersToVerify(-1)
			}
		case <-vt.terminalCh:
			return
		}
	}
}

// selectPeersAndVerify func select at most n peers from (candidatePeers-badPeers) randomly and send verify request.
// when n<0, send to all the peers exclude badPeers.
func (vt *VerifyTask) selectPeersToVerify(n int) {
	var validPeers []VerifyPeer
	candidatePeers := vt.candidatePeers.GetVerifyPeers()
	for _, p := range candidatePeers {
		if _, ok := vt.BadPeers[p.ID()]; !ok {
			validPeers = append(validPeers, p)
		}
	}
	// if
	if n < 0 || n >= len(validPeers) {
		for _, p := range validPeers {
			p.RequestRoot(vt.blockHeader.Number.Uint64(), vt.blockHeader.Hash(), vt.diffhash)
		}
		return
	}

	// if n < len(validPeers), select n peers from validPeers randomly.
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(validPeers), func(i, j int) { validPeers[i], validPeers[j] = validPeers[j], validPeers[i] })
	for i := 0; i < n; i++ {
		p := validPeers[i]
		p.RequestRoot(vt.blockHeader.Number.Uint64(), vt.blockHeader.Hash(), vt.diffhash)
	}
}

func (vt *VerifyTask) compareRootHashAndWrite(msg VerifyMessage, verifyCh chan common.Hash) {
	if msg.verifyResult.Root == vt.blockHeader.Root {
		blockhash := msg.verifyResult.BlockHash
		rawdb.MarkTrustBlock(vt.db, blockhash)
		// write back to manager so that manager can cache the result and delete this task.
		verifyCh <- blockhash
	} else {
		vt.BadPeers[msg.peerId] = struct{}{}
	}
}

type VerifyPeer interface {
	RequestRoot(blockNumber uint64, blockHash common.Hash, diffHash common.Hash) error
	ID() string
}

type VerifyPeers interface {
	GetVerifyPeers() []VerifyPeer
}

type VerifyMode uint32

const (
	LocalVerify VerifyMode = iota //
	FullVerify
	InsecureVerify
	NoneVerify
)

func (mode VerifyMode) IsValid() bool {
	return mode >= LocalVerify && mode <= NoneVerify
}

func (mode VerifyMode) String() string {
	switch mode {
	case LocalVerify:
		return "local"
	case FullVerify:
		return "full"
	case InsecureVerify:
		return "insecure"
	case NoneVerify:
		return "none"
	default:
		return "unknown"
	}
}

func (mode VerifyMode) MarshalText() ([]byte, error) {
	switch mode {
	case LocalVerify:
		return []byte("local"), nil
	case FullVerify:
		return []byte("full"), nil
	case InsecureVerify:
		return []byte("insecure"), nil
	case NoneVerify:
		return []byte("none"), nil
	default:
		return nil, fmt.Errorf("unknown verify mode %d", mode)
	}
}

func (mode *VerifyMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "local":
		*mode = LocalVerify
	case "full":
		*mode = FullVerify
	case "insecure":
		*mode = InsecureVerify
	case "none":
		*mode = NoneVerify
	default:
		return fmt.Errorf(`unknown sync mode %q, want "full", "light" or "insecure"`, text)
	}
	return nil
}

func (mode *VerifyMode) NeedRemoteVerify() bool {
	return *mode == FullVerify || *mode == InsecureVerify
}
