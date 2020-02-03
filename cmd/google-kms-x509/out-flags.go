package main

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	outFilePath string
)

func addOutFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&outFilePath, "out", "o", "-", "output file path, '-' for stdout")
}

func convertOutFlagsToFile() *os.File {
	if outFilePath == "-" {
		return os.Stdout
	}

	out, err := os.Create(outFilePath)

	if err != nil {
		panic(err)
	}

	return out
}
