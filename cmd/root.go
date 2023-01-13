package cmd

import (
	"fwtapper/cmd/recieve"
	"fwtapper/cmd/transmit"

	"github.com/spf13/cobra"
)

var rootCmd = cobra.Command{
	Use:  "fwtapper",
	Long: "An in-kernel traffic tapper based on eBPF.",
}

func init() {
	rootCmd.AddCommand(&transmit.Cmd)
	rootCmd.AddCommand(&recieve.Cmd)
}

func Execute() error {
	return rootCmd.Execute()
}
