package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/prysmaticlabs/prysm/io/file"

	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/cmd"
	"github.com/prysmaticlabs/prysm/cmd/validator/flags"
	"github.com/prysmaticlabs/prysm/config/features"
	"github.com/prysmaticlabs/prysm/crypto/bls"
	"github.com/prysmaticlabs/prysm/io/prompt"
	ethpbservice "github.com/prysmaticlabs/prysm/proto/eth/service"
	"github.com/prysmaticlabs/prysm/runtime/tos"
	"github.com/prysmaticlabs/prysm/validator/accounts"
	"github.com/prysmaticlabs/prysm/validator/accounts/iface"
	"github.com/prysmaticlabs/prysm/validator/accounts/userprompt"
	"github.com/prysmaticlabs/prysm/validator/accounts/wallet"
	"github.com/prysmaticlabs/prysm/validator/keymanager"
	"github.com/urfave/cli/v2"
)

const (
	newPromptText = "Enter the directory where your keystore file will be written to"
)

// Commands for managing Prysm validator accounts.
var accountsCommands = &cli.Command{
	Name:     "accounts",
	Category: "accounts",
	Usage:    "defines commands for interacting with Ethereum validator accounts",
	Subcommands: []*cli.Command{
		{
			Name:        "new",
			Description: `Create a new account.`,
			Flags: cmd.WrapFlags([]cli.Flag{
				flags.WalletDirFlag,
				flags.WalletPasswordFileFlag,
				flags.DeletePublicKeysFlag,
				features.Mainnet,
				features.PyrmontTestnet,
				features.PraterTestnet,
				cmd.AcceptTosFlag,
			}),
			Before: func(cliCtx *cli.Context) error {
				if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
					return err
				}
				return tos.VerifyTosAcceptedOrPrompt(cliCtx)
			},
			Action: func(cliCtx *cli.Context) error {
				features.ConfigureValidator(cliCtx)
				if err := CreateAccountCli(cliCtx); err != nil {
					log.Fatalf("Could not create account: %v", err)
				}
				return nil
			},
		},
		{
			Name:        "delete",
			Description: `deletes the selected accounts from a users wallet.`,
			Flags: cmd.WrapFlags([]cli.Flag{
				flags.WalletDirFlag,
				flags.WalletPasswordFileFlag,
				flags.DeletePublicKeysFlag,
				features.Mainnet,
				features.PyrmontTestnet,
				features.PraterTestnet,
				cmd.AcceptTosFlag,
			}),
			Before: func(cliCtx *cli.Context) error {
				if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
					return err
				}
				return tos.VerifyTosAcceptedOrPrompt(cliCtx)
			},
			Action: func(cliCtx *cli.Context) error {
				features.ConfigureValidator(cliCtx)
				if err := accounts.DeleteAccountCli(cliCtx); err != nil {
					log.Fatalf("Could not delete account: %v", err)
				}
				return nil
			},
		},
		{
			Name:        "list",
			Description: "Lists all validator accounts in a user's wallet directory",
			Flags: cmd.WrapFlags([]cli.Flag{
				flags.WalletDirFlag,
				flags.WalletPasswordFileFlag,
				flags.ShowDepositDataFlag,
				flags.ShowPrivateKeysFlag,
				flags.ListValidatorIndices,
				flags.BeaconRPCProviderFlag,
				cmd.GrpcMaxCallRecvMsgSizeFlag,
				flags.CertFlag,
				flags.GrpcHeadersFlag,
				flags.GrpcRetriesFlag,
				flags.GrpcRetryDelayFlag,
				features.Mainnet,
				features.PyrmontTestnet,
				features.PraterTestnet,
				cmd.AcceptTosFlag,
			}),
			Before: func(cliCtx *cli.Context) error {
				if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
					return err
				}
				return tos.VerifyTosAcceptedOrPrompt(cliCtx)
			},
			Action: func(cliCtx *cli.Context) error {
				features.ConfigureValidator(cliCtx)
				if err := accounts.ListAccountsCli(cliCtx); err != nil {
					log.Fatalf("Could not list accounts: %v", err)
				}
				return nil
			},
		},
		{
			Name: "backup",
			Description: "backup accounts into EIP-2335 compliant keystore.json files zipped into a backup.zip file " +
				"at a desired output directory. Accounts to backup can also " +
				"be specified programmatically via a --backup-for-public-keys flag which specifies a comma-separated " +
				"list of hex string public keys",
			Flags: cmd.WrapFlags([]cli.Flag{
				flags.WalletDirFlag,
				flags.WalletPasswordFileFlag,
				flags.BackupDirFlag,
				flags.BackupPublicKeysFlag,
				flags.BackupPasswordFile,
				features.Mainnet,
				features.PyrmontTestnet,
				features.PraterTestnet,
				cmd.AcceptTosFlag,
			}),
			Before: func(cliCtx *cli.Context) error {
				if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
					return err
				}
				return tos.VerifyTosAcceptedOrPrompt(cliCtx)
			},
			Action: func(cliCtx *cli.Context) error {
				features.ConfigureValidator(cliCtx)
				if err := accounts.BackupAccountsCli(cliCtx); err != nil {
					log.Fatalf("Could not backup accounts: %v", err)
				}
				return nil
			},
		},
		{
			Name:        "import",
			Description: `imports Ethereum validator accounts stored in EIP-2335 keystore.json files from an external directory`,
			Flags: cmd.WrapFlags([]cli.Flag{
				flags.WalletDirFlag,
				flags.KeysDirFlag,
				flags.WalletPasswordFileFlag,
				flags.AccountPasswordFileFlag,
				flags.ImportPrivateKeyFileFlag,
				features.Mainnet,
				features.PyrmontTestnet,
				features.PraterTestnet,
				cmd.AcceptTosFlag,
			}),
			Before: func(cliCtx *cli.Context) error {
				if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
					return err
				}
				return tos.VerifyTosAcceptedOrPrompt(cliCtx)
			},
			Action: func(cliCtx *cli.Context) error {
				features.ConfigureValidator(cliCtx)
				if err := accounts.ImportAccountsCli(cliCtx); err != nil {
					log.Fatalf("Could not import accounts: %v", err)
				}
				return nil
			},
		},
		{
			Name:        "voluntary-exit",
			Description: "Performs a voluntary exit on selected accounts",
			Flags: cmd.WrapFlags([]cli.Flag{
				flags.WalletDirFlag,
				flags.WalletPasswordFileFlag,
				flags.AccountPasswordFileFlag,
				flags.VoluntaryExitPublicKeysFlag,
				flags.BeaconRPCProviderFlag,
				cmd.GrpcMaxCallRecvMsgSizeFlag,
				flags.CertFlag,
				flags.GrpcHeadersFlag,
				flags.GrpcRetriesFlag,
				flags.GrpcRetryDelayFlag,
				flags.ExitAllFlag,
				features.Mainnet,
				features.PyrmontTestnet,
				features.PraterTestnet,
				cmd.AcceptTosFlag,
			}),
			Before: func(cliCtx *cli.Context) error {
				if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
					return err
				}
				return tos.VerifyTosAcceptedOrPrompt(cliCtx)
			},
			Action: func(cliCtx *cli.Context) error {
				features.ConfigureValidator(cliCtx)
				if err := accounts.ExitAccountsCli(cliCtx, os.Stdin); err != nil {
					log.Fatalf("Could not perform voluntary exit: %v", err)
				}
				return nil
			},
		},
	},
}

func CreateAccountCli(cliCtx *cli.Context) error {
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

	// Input the directory where they wish to store created keystore.
	createDir, err := userprompt.InputDirectory(cliCtx, newPromptText, flags.KeysDirFlag)
	if err != nil {
		return errors.Wrap(err, "could not parse keystore directory")
	}
	if err := file.MkdirAll(createDir); err != nil {
		return errors.Wrapf(err, "could not create directory at path: %s", createDir)
	}

	// Ask the user for their desired password for their backed up accounts.
	createPassword, err := prompt.InputPassword(
		cliCtx,
		flags.AccountPasswordFileFlag,
		"Enter a new password for your created accounts",
		"Confirm new password",
		true,
		prompt.ValidatePasswordInput,
	)
	if err != nil {
		return errors.Wrap(err, "could not determine password for new account")
	}

	encryptor := keystorev4.New()
	secretKey, err := bls.RandKey()
	if err != nil {
		return errors.Wrap(err, "could not generate bls secret key")
	}
	pubKeyBytes := secretKey.PublicKey().Marshal()
	cryptoFields, err := encryptor.Encrypt(secretKey.Marshal(), createPassword)
	if err != nil {
		return errors.Wrapf(err, "could not encrypt secret key for public key %#x", pubKeyBytes)
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return errors.Wrapf(err, "could not generate uuid")
	}
	keystore := &keymanager.Keystore{
		Crypto:  cryptoFields,
		ID:      id.String(),
		Pubkey:  fmt.Sprintf("%x", pubKeyBytes),
		Version: encryptor.Version(),
		Name:    encryptor.Name(),
	}

	encodedFile, err := json.MarshalIndent(keystore, "", "\t")
	if err != nil {
		return errors.Wrap(err, "could not marshal keystore to JSON file")
	}
	keystoreFile, err := os.Create(fmt.Sprintf("%s/keystore-%s.json", createDir, id.String()))
	if err != nil {
		return errors.Wrapf(err, "could not create keystore file")
	}
	if _, err := keystoreFile.Write(encodedFile); err != nil {
		return errors.Wrap(err, "could not write keystore file contents")
	}
	fmt.Println("Successfully create an account")

	fmt.Println("Importing accounts, this may take a while...")
	k, ok := km.(keymanager.Importer)
	if !ok {
		return errors.New("keymanager cannot import keystores")
	}
	statuses, err := accounts.ImportAccounts(cliCtx.Context, &accounts.ImportAccountsConfig{
		Importer:        k,
		Keystores:       []*keymanager.Keystore{keystore},
		AccountPassword: createPassword,
	})
	switch statuses[0].Status {
	case ethpbservice.ImportedKeystoreStatus_DUPLICATE:
		log.Warnf("Duplicate key %s found in import request, skipped", keystore.Pubkey)
	case ethpbservice.ImportedKeystoreStatus_ERROR:
		log.Warnf("Could not import keystore for %s: %s", keystore.Pubkey, statuses[0].Message)
	}
	fmt.Printf("Successfully imported created account, view it by running `accounts list`\n")
	return nil
}
