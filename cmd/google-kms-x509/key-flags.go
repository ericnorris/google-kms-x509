package main

import (
	"github.com/spf13/cobra"
)

var (
	kmsKey          string
	generateComment bool
)

func addKeyFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&kmsKey, "kms-key", "k", "", "Google KMS key resource ID")
	cmd.Flags().BoolVar(&generateComment, "generate-comment", true, "generate an x509 comment showing the Google KMS key resource ID used")
	cmd.MarkFlagRequired("kms-key")
}
