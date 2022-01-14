package core

import (
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

const verifiedCacheSize = 256

type VerifyManager struct {
	bc                   *BlockChain
	tasks                map[common.Hash]*VerifyTask
	peers                VerifyPeers
	verifiedCache        *lru.Cache
	allowUntrustedVerify bool
	verifyCh             chan common.Hash
	exitCh               chan struct{}
}

func NewVerifyManager(blockchain *BlockChain) *VerifyManager {
	verifiedCache, _ := lru.New(verifiedCacheSize)
	vm := &VerifyManager{
		bc:            blockchain,
		tasks:         make(map[common.Hash]*VerifyTask),
		verifiedCache: verifiedCache,
		verifyCh:      make(chan common.Hash),
		exitCh:        make(chan struct{}),
	}
	return vm
}

func (vm *VerifyManager) Start() {
	//read disk store to initial verified cache
	//load unverified blocks in a normalized chain and start a batch of verify task
	header := vm.bc.CurrentHeader()
	go vm.mainLoop(header)
}

func (vm *VerifyManager) Stop() {
	//stop all the tasks
	close(vm.exitCh)
}

func (vm *VerifyManager) mainLoop(header *types.Header) {
	//Start verify task from H to H-11 if need.
	vm.NewBlockVerifyTask(header)
	prune := time.NewTicker(time.Second)
	defer prune.Stop()
	for {
		select {
		case hash := <-vm.verifyCh:
			vm.cacheBlockVerified(hash)
			rawdb.WriteTrustBlockHash(vm.bc.db, hash)
			delete(vm.tasks, hash)
		case <-prune.C:
			for hash, task := range vm.tasks {
				if vm.bc.CurrentHeader().Number.Uint64()-task.blockHeader.Number.Uint64() > 15 {
					delete(vm.tasks, hash)
					close(task.terminalCh)
				}
			}
		case <-vm.exitCh:
			return
		}
	}
}

func (vm *VerifyManager) NewBlockVerifyTask(header *types.Header) {
	for i := 0; i <= 11; i++ {
		hash := header.Hash()
		//if verified cache record that this block has been verified, skip.
		if _, ok := vm.verifiedCache.Get(hash); ok {
			header = vm.bc.GetHeaderByHash(header.ParentHash)
			continue
		}
		//if there already has a verify task for this block, skip.
		if _, ok := vm.tasks[hash]; ok {
			header = vm.bc.GetHeaderByHash(header.ParentHash)
			continue
		}
		//if verified storage record that this block has been verified, skip.
		if rawdb.ReadTrustBlockHash(vm.bc.db, hash) {
			vm.cacheBlockVerified(hash)
			header = vm.bc.GetHeaderByHash(header.ParentHash)
			continue
		}
		diffLayer := vm.bc.GetTrustedDiffLayer(hash)
		//if this block has no diff, there is no need to verify it.
		var err error
		if diffLayer == nil {
			if diffLayer, err = vm.bc.GenerateDiffLayer(hash); err != nil {
				log.Error("failed to get diff layer", "block", hash, "number", header.Number, "error", err)
				header = vm.bc.GetHeaderByHash(header.ParentHash)
				continue
			}
		}
		diffHash, err := GetTrustedDiffHash(diffLayer)
		if err != nil {
			log.Error("failed to get diff hash", "block", hash, "number", header.Number, "error", err)
			header = vm.bc.GetHeaderByHash(header.ParentHash)
			continue
		}
		verifyTask := NewVerifyTask(diffHash, header, vm.peers, vm.bc.db, vm.verifyCh, vm.allowUntrustedVerify)
		vm.tasks[hash] = verifyTask
		header = vm.bc.GetHeaderByHash(header.ParentHash)
	}
}

func (vm *VerifyManager) cacheBlockVerified(hash common.Hash) {
	if vm.verifiedCache.Len() >= verifiedCacheSize {
		vm.verifiedCache.RemoveOldest()
	}
	vm.verifiedCache.Add(hash, true)
}

//CheckAncestorVerified function check whether H-11 block has been verified or it's a empty block.
//If not, the blockchain should stop to insert new block.
func (vm *VerifyManager) CheckAncestorVerified(header *types.Header) bool {
	//find header of H-11 block.
	header = vm.bc.GetHeaderByNumber(header.Number.Uint64() - 11)
	//If start from genesis block, there has not a H-11 block.
	if header == nil {
		return true
	}
	hash := header.Hash()
	//check whether H-11 block is a empty block.
	parent := vm.bc.GetHeaderByHash(hash)
	if header.TxHash == (common.Hash{}) && header.Root == parent.Root {
		return true
	}
	if _, ok := vm.verifiedCache.Get(hash); ok {
		return true
	}
	return rawdb.ReadTrustBlockHash(vm.bc.db, hash)
}

func (vm *VerifyManager) HandleRootResponse(vr *VerifyResult, pid string) error {
	if vt, ok := vm.tasks[vr.BlockHash]; ok {
		vt.messageCh <- VerifyMessage{verifyResult: vr, peerId: pid}
		return nil
	}
	return fmt.Errorf("")
}
