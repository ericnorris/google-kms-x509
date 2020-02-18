package main

import (
	"github.com/spf13/cobra"
)

var Version string

var mainCmd = &cobra.Command{
	Use:   "google-kms-x509",
	Short: "",
	Long:  ``,

	Version: Version,
}

func main() {
	mainCmd.AddCommand(generateCmd)
	mainCmd.AddCommand(signCmd)

	mainCmd.Execute()
}
