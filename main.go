package main

import (
	"context"
	"fmt"
	"os"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	api "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/spf13/cobra"
	"github.com/wealdtech/ethdo/util"
	"github.com/wealdtech/go-string2eth"
)

const (
	_exitSuccess = 0
	_exitFailure = 1
)

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

func checkValidatorsStatus(vals []*api.Validator) {
	for _, validator := range vals {
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
}

// THIS COMMAND IS A WIP MOST CODE IS FOR TESTING
func CheckValidatorStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "check the status of all validators",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			//checkErr := makeCheckErr(cmd)
			fmt.Println("Checking validator status")
			//val := "0xaba25098b1f698ff3f159337333c9a895d27fccdf78593d23c6e3b6af1c04a21d7321e2f64895cabab5450e9bada9aa2"
			vals := make([]string, 3)
			vals[0] = "198344"
			vals[1] = "198345"
			vals[2] = "198346"
			//vals[3] = "0x917f97c3e71c5e317eb3d14d358d1b48d41cb753ab2dad742400936e62461672589d1f72cb9051e758dad817d45fa33f"

			ctx := context.Background()

			eth2Client, err := util.ConnectToBeaconNode(ctx,
				"",
				10*time.Second,
				false)
			errCheck(err, "Failed to connect to Ethereum 2 beacon node")

			validators, err := util.ParseValidators(ctx, eth2Client.(eth2client.ValidatorsProvider), vals, "head")
			errCheck(err, "Failed to obtain validator")

			checkValidatorsStatus(validators)

			network, err := util.Network(ctx, eth2Client)
			errCheck(err, "Failed to obtain network")
			fmt.Sprintf("Network is %s", network)

		},
	}
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

	rootCmd.AddCommand(CheckValidatorStatus())
	rootCmd.AddCommand(Deposit())
	rootCmd.AddCommand(BlsExecutionChange())
	rootCmd.AddCommand(Withdrawal())

	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
