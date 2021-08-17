package main

import (
	"github.com/spf13/cobra"
)

var (
	crlDistributionPoints []string
)

func addCrlFlag(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(
		&crlDistributionPoints,
		"crl-dist-points",
		[]string{},
		"CRL Distribution Points for x509 v3 certificate extension",
	)
}
