package core

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"

	"math/rand"
	"time"
)

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

	vt.selectPeersToVerify(vt.candidatePeers.GetVerifyPeers(), 3)
	resend := time.NewTicker(2 * time.Second)
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
			case types.StatusBlockTooNew, types.StatusBlockNewer, types.StatusPossibleFork:
				log.Info("return msg from peer %s for block %s is %s", msg.peerId, msg.verifyResult.BlockHash, msg.verifyResult.Status.Msg)
			}
		case <-resend.C:
			//if a task has run over 300s, try all the vaild peers to verify.
			if time.Now().Second()-vt.startAt.Second() < 300 {
				vt.selectPeersToVerify(vt.candidatePeers.GetVerifyPeers(), 1)
			} else {
				vt.selectPeersToVerify(vt.candidatePeers.GetVerifyPeers(), -1)
			}
		case <-vt.terminalCh:
			return
		}
	}
}

// selectPeersAndVerify func select at most n peers from (candidatePeers-badPeers) randomly and send verify request.
//when n<0, send to all the peers exclude badPeers.
func (vt *VerifyTask) selectPeersToVerify(candidatePeers []VerifyPeer, n int) {
	var validPeers []VerifyPeer
	for _, p := range candidatePeers {
		if _, ok := vt.BadPeers[p.ID()]; !ok {
			validPeers = append(validPeers, p)
		}
	}
	if n < 0 || n >= len(validPeers) {
		for _, p := range validPeers {
			p.RequestRoot(vt.blockHeader.Number.Uint64(), vt.blockHeader.Hash(), vt.diffhash)
		}
		return
	}

	//if n < len(validPeers), select n peers from validPeers randomly.
	for i := 0; i < n; i++ {
		s := rand.NewSource(time.Now().Unix())
		r := rand.New(s)
		p := validPeers[r.Intn(len(validPeers))]
		p.RequestRoot(vt.blockHeader.Number.Uint64(), vt.blockHeader.Hash(), vt.diffhash)
	}
}

func (vt *VerifyTask) compareRootHashAndWrite(msg VerifyMessage, verifyCh chan common.Hash) {
	if msg.verifyResult.Root == vt.blockHeader.Root {
		blockhash := msg.verifyResult.BlockHash
		rawdb.WriteTrustBlockHash(vt.db, blockhash)
		//write back to manager so that manager can cache the result and delete this task.
		verifyCh <- blockhash
		vt.terminalCh <- struct{}{}
	} else {
		vt.BadPeers[msg.peerId] = struct{}{}
	}
}
