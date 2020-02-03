package main

import (
	"github.com/spf13/cobra"
)

var (
	days int
)

func addDaysFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&days, "days", 0, "days until expiration")
	cmd.MarkFlagRequired("days")
}
