package main

import (
	"github.com/ericnorris/google-kms-x509/internal/cli"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "",
	Long:  ``,
}

var generateRootCACmd = &cobra.Command{
	Use:   "root-ca",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cli.GenerateRootCA(
			kmsKey,
			convertSubjectFlagsToName(),
			rootCADays,
			convertOutFlagsToFile(),
		)
	},
}

var generateCSRCmd = &cobra.Command{
	Use:   "csr",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cli.GenerateCSR(
			kmsKey,
			convertSubjectFlagsToName(),
			convertOutFlagsToFile(),
		)
	},
}

var (
	rootCADays int
)

func init() {
	addKeyFlags(generateRootCACmd)
	addKeyFlags(generateCSRCmd)

	addSubjectFlags(generateRootCACmd)
	addSubjectFlags(generateCSRCmd)

	addOutFlags(generateRootCACmd)
	addOutFlags(generateCSRCmd)

	generateRootCACmd.Flags().IntVar(&rootCADays, "days", 0, "days until expiration")
	generateRootCACmd.MarkFlagRequired("days")

	generateCmd.AddCommand(generateRootCACmd)
	generateCmd.AddCommand(generateCSRCmd)
}
