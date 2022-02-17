package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	runtimeDebug "runtime/debug"

	"github.com/ethereum/go-ethereum/params"
	"github.com/prysmaticlabs/prysm/cmd"
	"github.com/prysmaticlabs/prysm/config/features"
	"github.com/urfave/cli/v2"
)

// Git SHA1 commit hash of the release (set via linker flags)
var gitCommit = ""
var gitDate = ""

var log = logrus.WithField("prefix", "validator")

var app *cli.App

var appFlags []cli.Flag

func startNode(ctx *cli.Context) error {
	fmt.Printf("Hello validator!\n")
	return nil
}

func init() {
	appFlags = cmd.WrapFlags(append(appFlags, features.ValidatorFlags...))
}

// Commonly used command line flags.
var (
	passphraseFlag = cli.StringFlag{
		Name:  "passwordfile",
		Usage: "the file that contains the password for the keyfile",
	}
	jsonFlag = cli.BoolFlag{
		Name:  "json",
		Usage: "output JSON instead of human-readable format",
	}
)

func main() {
	app := cli.App{}
	app.Name = filepath.Base(os.Args[0])
	app.Usage = "a validator key manager"
	app.Version = params.VersionWithCommit(gitCommit, gitDate)
	app.Action = startNode
	app.Commands = []*cli.Command{
		walletCommands,
		accountsCommands,
		exampleCommands,
	}

	app.Flags = appFlags

	app.Before = func(context *cli.Context) error {
		return nil
	}

	app.After = func(context *cli.Context) error {
		return nil
	}

	defer func() {
		if x := recover(); x != nil {
			log.Errorf("Runtime panic: %v\n%v", x, string(runtimeDebug.Stack()))
			panic(x)
		}
	}()

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
