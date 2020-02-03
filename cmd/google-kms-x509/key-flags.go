package main

import (
	"github.com/spf13/cobra"
)

var (
	kmsKey string
)

func addKeyFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&kmsKey, "kms-key", "k", "", "Google KMS key resource ID")
	cmd.MarkFlagRequired("kms-key")
}
