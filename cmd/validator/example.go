package main

import (
	"fmt"

	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/cmd"
	"github.com/prysmaticlabs/prysm/cmd/validator/flags"
	"github.com/prysmaticlabs/prysm/config/features"
	"github.com/prysmaticlabs/prysm/crypto/bls"
	"github.com/prysmaticlabs/prysm/crypto/bls/common"
	validatorpb "github.com/prysmaticlabs/prysm/proto/prysm/v1alpha1/validator-client"
	"github.com/prysmaticlabs/prysm/runtime/tos"
	"github.com/prysmaticlabs/prysm/validator/accounts"
	"github.com/prysmaticlabs/prysm/validator/accounts/iface"
	"github.com/prysmaticlabs/prysm/validator/accounts/wallet"
	"github.com/prysmaticlabs/prysm/validator/keymanager"
	"github.com/urfave/cli/v2"
)

const (
	signData = "Hello, Welcome to bls world!"
)

// Commands for managing Prysm validator accounts.
var exampleCommands = &cli.Command{
	Name:        "example",
	Category:    "validator",
	Usage:       "run bls example",
	Description: `run bls example.`,
	Flags: cmd.WrapFlags([]cli.Flag{
		flags.WalletDirFlag,
	}),
	Before: func(cliCtx *cli.Context) error {
		if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
			return err
		}
		return tos.VerifyTosAcceptedOrPrompt(cliCtx)
	},
	Action: func(cliCtx *cli.Context) error {
		features.ConfigureValidator(cliCtx)
		if err := run(cliCtx); err != nil {
			log.Fatalf("Example failed: %v", err)
		}
		return nil
	},
}

func run(cliCtx *cli.Context) error {
	w, err := wallet.OpenWalletOrElseCli(cliCtx, func(cliCtx *cli.Context) (*wallet.Wallet, error) {
		return nil, wallet.ErrNoWalletFound
	})
	if err != nil {
		return errors.Wrap(err, "could not initialize wallet")
	}
	if w.KeymanagerKind() != keymanager.Imported {
		return errors.New(
			"remote wallets cannot backup accounts",
		)
	}
	km, err := w.InitializeKeymanager(cliCtx.Context, iface.InitKeymanagerConfig{ListenForChanges: false})
	if err != nil {
		return errors.Wrap(err, accounts.ErrCouldNotInitializeKeymanager)
	}

	pubKeys, err := km.FetchValidatingPublicKeys(cliCtx.Context)
	if err != nil {
		return errors.Wrap(err, "could not fetch validating public keys")
	}

	// Sign the hash of sign data, not the data itself.
	hashData := common2.BytesToHash([]byte(signData))

	// Fetch the first pubKey as validator's bls public key.
	pubKey := pubKeys[0]
	blsPubKey, err := bls.PublicKeyFromBytes(pubKey[:])
	if err != nil {
		return errors.Wrap(err, "convert public key from bytes to bls failed")
	}
	sig, err := km.Sign(cliCtx.Context, &validatorpb.SignRequest{
		PublicKey:   pubKey[:],
		SigningRoot: hashData[:],
	})
	if err != nil {
		return errors.Wrap(err, "key manager sign failed")
	}

	if !sig.Verify(blsPubKey, hashData[:]) {
		return errors.New("verify bls signature failed.")
	}

	// Aggregate signature and verify
	// Create another bls account
	newKey, err := bls.RandKey()
	if err != nil {
		return errors.Wrap(err, "create new bls account failed")
	}
	newSig := newKey.Sign(hashData[:])

	aggSig := bls.AggregateSignatures([]common.Signature{sig, newSig})
	if !aggSig.FastAggregateVerify([]bls.PublicKey{newKey.PublicKey(), blsPubKey}, hashData) {
		return errors.New("fast aggregated verify bls signature failed.")
	}

	// Try to use aggregated public key to verify aggregated signature.
	aggPub, err := bls.AggregatePublicKeys([][]byte{pubKey[:], newKey.PublicKey().Marshal()})
	if err != nil {
		return errors.Wrap(err, "could not aggregate public keys")
	}
	if !aggSig.Verify(aggPub, hashData[:]) {
		return errors.New("aggregated public keys verify  aggregated bls signature failed.")
	}

	fmt.Println("Congratulations, all examples successful!")
	return nil
}
