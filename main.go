package main

import (
	"context"
	"encoding/hex"

	"fmt"
	"os"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	hbls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	util "github.com/wealdtech/ethdo/util"
	goEthUtil "github.com/wealdtech/go-eth2-util"
	"github.com/wealdtech/go-string2eth"
)

func init() {
	hbls.Init(hbls.BLS12_381)
	hbls.SetETHmode(hbls.EthModeLatest)
}

const (
	_exitSuccess = 0
	_exitFailure = 1
)

func makeCheckErr(cmd *cobra.Command) func(err error, msg string) {
	return func(err error, msg string) {
		if err != nil {
			if msg != "" {
				err = fmt.Errorf("%s: %v", msg, err)
			}
			cmd.PrintErr(err)
			os.Exit(1)
		}
	}
}

// errCheck checks for an error and quits if it is present
func errCheck(err error, msg string) {
	if err != nil {
		if msg == "" {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		} else {
			fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err.Error())
		}
		os.Exit(1)
	}
}

// Narrow pubkeys: we don't want 0xAb... to be different from ab...
func narrowedPubkey(pub string) string {
	return strings.TrimPrefix(strings.ToLower(pub), "0x")
}

func mnemonicToSeed(mnemonic string) (seed []byte, err error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is not valid")
	}
	return bip39.NewSeed(mnemonic, ""), nil
}

func validatorsFromMnemonic(mnemonic string, accountMin uint64, accountMax uint64) map[string]string {
	seed, err := mnemonicToSeed(mnemonic)
	errCheck(err, "failed to generate seed from mnemonic")
	var validators map[string]string
	validators = make(map[string]string)
	for i := accountMin; i < accountMax; i++ {
		idx := i
		path := fmt.Sprintf("m/12381/3600/%d/0/0", idx)
		validatorPrivkey, err := goEthUtil.PrivateKeyFromSeedAndPath(seed, path)
		errCheck(err, "failed to derive validator private key")
		pubkey := narrowedPubkey(hex.EncodeToString(validatorPrivkey.PublicKey().Marshal()))
		validators[fmt.Sprintf("%#x", pubkey)] = hex.EncodeToString(validatorPrivkey.Marshal())
	}

	return validators
}

func printValidatorStatus(validator *api.Validator) {
	if validator.Status.IsPending() || validator.Status.HasActivated() {
		fmt.Printf("Index: %d\n", validator.Index)
	}

	if validator.Status.IsPending() {
		fmt.Printf("Activation eligibility epoch: %d\n", validator.Validator.ActivationEligibilityEpoch)
	}
	if validator.Status.HasActivated() {
		fmt.Printf("Activation epoch: %d\n", validator.Validator.ActivationEpoch)
	}
	fmt.Printf("Public key: %#x\n", validator.Validator.PublicKey)

	fmt.Printf("Status: %v\n", validator.Status)
	switch validator.Status {
	case api.ValidatorStateActiveExiting, api.ValidatorStateActiveSlashed:
		fmt.Printf("Exit epoch: %d\n", validator.Validator.ExitEpoch)
	case api.ValidatorStateExitedUnslashed, api.ValidatorStateExitedSlashed:
		fmt.Printf("Withdrawable epoch: %d\n", validator.Validator.WithdrawableEpoch)
	}
	fmt.Printf("Balance: %s\n", string2eth.GWeiToString(uint64(validator.Balance), true))
	if validator.Status.IsActive() {
		fmt.Printf("Effective balance: %s\n", string2eth.GWeiToString(uint64(validator.Validator.EffectiveBalance), true))
	}

	fmt.Printf("Withdrawal credentials: %#x\n", validator.Validator.WithdrawalCredentials)
}

func printValidatorsStatus(vals []*api.Validator) {
	for _, validator := range vals {
		printValidatorStatus(validator)
	}
}

func checkValidatorsStatus(vals map[string]string) []*api.Validator {
	ctx := context.Background()

	eth2Client, err := util.ConnectToBeaconNode(ctx,
		"",
		10*time.Second,
		false)
	errCheck(err, "Failed to connect to Ethereum 2 beacon node")
	validatorPubKeys := []string{}
	for valPubKey, _ := range vals {
		validatorPubKeys = append(validatorPubKeys, valPubKey)
	}
	validators, err := util.ParseValidators(ctx, eth2Client.(eth2client.ValidatorsProvider), validatorPubKeys, "head")
	errCheck(err, "Failed to obtain validator")

	network, err := util.Network(ctx, eth2Client)
	errCheck(err, "Failed to obtain network")
	fmt.Sprintf("Network is %s", network)
	return validators
}

// THIS COMMAND IS A WIP MOST CODE IS FOR TESTING
func Status() *cobra.Command {
	var sourceMnemonic string
	var accountMin uint64
	var accountMax uint64

	cmd := &cobra.Command{
		Use:   "status",
		Short: "check the status of all validators",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Checking validator status")

			vals := validatorsFromMnemonic(sourceMnemonic, accountMin, accountMax)

			validators := checkValidatorsStatus(vals)
			printValidatorsStatus(validators)
		},
	}

	cmd.Flags().StringVar(&sourceMnemonic, "source-mnemonic", "", "The validators mnemonic to source account keys from.")
	cmd.Flags().Uint64Var(&accountMin, "source-min", 0, "Minimum validator index in HD path range (incl.)")
	cmd.Flags().Uint64Var(&accountMax, "source-max", 0, "Maximum validator index in HD path range (excl.)")

	return cmd
}

func Deposit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deposit",
		Short: "build and submit deposit messages for all validators...",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Building and submitting deposit messages for all validators...")
		},
	}
	return cmd
}

func BlsExecutionChange() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bls-change",
		Short: "build and submit BLS Execution Change messages for all validators...",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Building and submitting BLS Execution Change messages...")
		},
	}
	return cmd
}

func Withdrawal() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "withdrawal",
		Short: "build and submit withdrawal messages for all validators...",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Building and submitting withdrawal messages for all validators...")
		},
	}
	return cmd
}

func main() {

	rootCmd := &cobra.Command{
		Use:   "shapella-fuzz",
		Short: "Create Deposits, BlsExecutionChange, and Withdrawal messages",
		Long: "Create Deposits, BlsExecutionChange, and Withdrawal messages." +
			"standing on the shoulders of ethdo and eth2-val-tools",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	rootCmd.AddCommand(Status())
	rootCmd.AddCommand(Deposit())
	rootCmd.AddCommand(BlsExecutionChange())
	rootCmd.AddCommand(Withdrawal())

	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
