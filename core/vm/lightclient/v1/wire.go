// Package v1 is used for tendermint v0.31.12 and its compatible version.
package v1

import (
	"github.com/tendermint/go-amino"
	cryptoAmino "github.com/tendermint/tendermint/crypto/encoding/amino"
)

type Codec = amino.Codec

var Cdc *Codec

func init() {
	cdc := amino.NewCodec()
	cryptoAmino.RegisterAmino(cdc)
	Cdc = cdc.Seal()
}
