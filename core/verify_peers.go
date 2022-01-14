package core

import "github.com/ethereum/go-ethereum/common"

type VerifyPeer interface {
	RequestRoot(blockNumber uint64, blockHash common.Hash, diffHash common.Hash) error
	ID() string
}

type VerifyPeers interface {
	GetVerifyPeers() []VerifyPeer
}
