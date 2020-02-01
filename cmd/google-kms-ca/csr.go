package main

import (
  "fmt"

  "github.com/spf13/cobra"
)

func init() {
  rootCmd.AddCommand(csrCmd)
}

var csrCmd = &cobra.Command{
  Use:   "csr",
  Short: "",
  Long:  ``,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("meow")
  },
}
