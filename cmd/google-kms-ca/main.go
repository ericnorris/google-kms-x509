package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "google-kms-ca",
	Short: "",
	Long:  ``,
}

func main() {
	rootCmd.Execute()
}
