package trust

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"golang.org/x/crypto/sha3"
)

// Constants to match up protocol versions and messages
const (
	Trust1 = 1
)

// ProtocolName is the official short name of the `trust` protocol used during
// devp2p capability negotiation.
const ProtocolName = "trust"

// ProtocolVersions are the supported versions of the `trust` protocol (first
// is primary).
var ProtocolVersions = []uint{Trust1}

// protocolLengths are the number of implemented message corresponding to
// different protocol versions.
var protocolLengths = map[uint]uint64{Trust1: 3}

// maxMessageSize is the maximum cap on the size of a protocol message.
const maxMessageSize = 10 * 1024 * 1024

const (
	GetRootByDiffHashMsg  = 0x00
	GetRootByDiffLayerMsg = 0x01
	RootResponseMsg       = 0x02
)

var defaultExtra = []byte{0x00}

var (
	errMsgTooLarge    = errors.New("message too long")
	errDecode         = errors.New("invalid message")
	errInvalidMsgCode = errors.New("invalid message code")
	errUnexpectedMsg  = errors.New("unexpected message code")
)

type RootResponseStatus struct {
	Code uint16
	Msg  string
}

var (
	// StatusVerified means the processing of request going as expected and found the root correctly.
	StatusVerified          = RootResponseStatus{Code: 0x100}
	StatusFullVerified      = RootResponseStatus{Code: 0x101, Msg: "state root full verified"}
	StatusPartialVerified   = RootResponseStatus{Code: 0x102, Msg: "state root partial verified, need difflayer to be full verified"}
	StatusUntrustedVerified = RootResponseStatus{Code: 0x103, Msg: "state root untrusted verified, because of missing MPT data in verify node"}

	// StatusFailed means the request has something wrong.
	StatusFailed           = RootResponseStatus{Code: 0x200}
	StatusDiffHashMismatch = RootResponseStatus{Code: 0x201, Msg: "verify failed because of blockhash mismatch with diffhash"}
	StatusImpossibleFork   = RootResponseStatus{Code: 0x202, Msg: "verify failed because of impossible fork detected"}

	// StatusUncertain means verify node can't give a certain result of the request.
	StatusUncertain      = RootResponseStatus{Code: 0x300}
	StatusBlockTooNew    = RootResponseStatus{Code: 0x301, Msg: "can’t verify because of block number larger than current height more than 11"}
	StatusBlockNewer     = RootResponseStatus{Code: 0x302, Msg: "can’t verify because of block number larger than current height"}
	StatusPossibleFork   = RootResponseStatus{Code: 0x303, Msg: "can’t verify because of possible fork detected"}
	StatusRequestTooBusy = RootResponseStatus{Code: 0x304, Msg: "can’t verify because of request too busy"}

	// StatusUnexpectedError is unexpected internal error.
	StatusUnexpectedError = RootResponseStatus{Code: 0x400, Msg: "can’t verify because of unexpected internal error"}
)

// Packet represents a p2p message in the `trust` protocol.
type Packet interface {
	Name() string // Name returns a string corresponding to the message type.
	Kind() byte   // Kind returns the message type.
}

type GetRootByDiffHashPacket struct {
	RequestId   uint64
	BlockNumber uint64
	BlockHash   common.Hash
	DiffHash    common.Hash
}

type GetRootByDiffLayerPacket struct {
	RequestId uint64
	DiffLayer rlp.RawValue
}

type RootResponsePacket struct {
	RequestId   uint64
	Status      RootResponseStatus
	BlockNumber uint64
	BlockHash   common.Hash
	Root        common.Hash
	Extra       rlp.RawValue // for extension
}

func (p *GetRootByDiffLayerPacket) Unpack() (*types.DiffLayer, error) {
	var diff types.DiffLayer
	hasher := sha3.NewLegacyKeccak256()
	err := rlp.DecodeBytes(p.DiffLayer, &diff)
	if err != nil {
		return nil, fmt.Errorf("%w: diff layer %v", errDecode, err)
	}

	_, err = hasher.Write(p.DiffLayer)
	if err != nil {
		return nil, err
	}
	var diffHash common.Hash
	hasher.Sum(diffHash[:0])
	diff.DiffHash = diffHash

	return &diff, nil
}

func (*GetRootByDiffHashPacket) Name() string { return "GetRootByDiffHash" }
func (*GetRootByDiffHashPacket) Kind() byte   { return GetRootByDiffHashMsg }

func (*GetRootByDiffLayerPacket) Name() string { return "GetRootByDiffLayer" }
func (*GetRootByDiffLayerPacket) Kind() byte   { return GetRootByDiffLayerMsg }

func (*RootResponsePacket) Name() string { return "RootResponse" }
func (*RootResponsePacket) Kind() byte   { return RootResponseMsg }
