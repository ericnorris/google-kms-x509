package main

import (
	"github.com/spf13/cobra"
)

var mainCmd = &cobra.Command{
	Use:   "google-kms-x509",
	Short: "",
	Long:  ``,
}

func main() {
	mainCmd.AddCommand(generateCmd)
	mainCmd.AddCommand(signCmd)

	mainCmd.Execute()
}
