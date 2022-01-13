package trust

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
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
var protocolLengths = map[uint]uint64{Trust1: 2}

// maxMessageSize is the maximum cap on the size of a protocol message.
const maxMessageSize = 10 * 1024 * 1024

const (
	RequestRootMsg = 0x00
	RespondRootMsg = 0x01
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
	StatusUntrustedVerified = RootResponseStatus{Code: 0x102, Msg: "state root untrusted verified, because of difflayer not found"}

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

type RootRequestPacket struct {
	RequestId   uint64
	BlockNumber uint64
	BlockHash   common.Hash
	DiffHash    common.Hash
}

type RootResponsePacket struct {
	RequestId   uint64
	Status      RootResponseStatus
	BlockNumber uint64
	BlockHash   common.Hash
	Root        common.Hash
	Extra       rlp.RawValue // for extension
}

func (*RootRequestPacket) Name() string { return "RequestRoot" }
func (*RootRequestPacket) Kind() byte   { return RequestRootMsg }

func (*RootResponsePacket) Name() string { return "RootResponse" }
func (*RootResponsePacket) Kind() byte   { return RespondRootMsg }
