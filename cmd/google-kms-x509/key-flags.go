package main

import (
	"github.com/spf13/cobra"
)

var (
	kmsKey        string
	kmsKeyComment bool
)

func addKeyFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&kmsKey, "kms-key", "k", "", "Google KMS key resource ID")
	cmd.Flags().BoolVar(&kmsKeyComment, "kms-key-comment", true, "use Google KMS key fully qualified path as x.509 comment")
	cmd.MarkFlagRequired("kms-key")
}
