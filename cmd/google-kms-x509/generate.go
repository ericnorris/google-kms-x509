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
			generateComment,
			convertSubjectFlagsToName(),
			days,
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
			generateComment,
			convertSubjectFlagsToName(),
			convertOutFlagsToFile(),
		)
	},
}

func init() {
	addKeyFlags(generateRootCACmd)
	addKeyFlags(generateCSRCmd)

	addSubjectFlags(generateRootCACmd)
	addSubjectFlags(generateCSRCmd)

	addOutFlags(generateRootCACmd)
	addOutFlags(generateCSRCmd)

	// 'generate root-ca' only flags
	addDaysFlags(generateRootCACmd)

	generateCmd.AddCommand(generateRootCACmd)
	generateCmd.AddCommand(generateCSRCmd)
}
