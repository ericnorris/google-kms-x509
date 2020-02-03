package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"

	"github.com/ericnorris/google-kms-x509/internal/cli"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "",
	Long:  ``,
}

var signIntermediateCACmd = &cobra.Command{
	Use:   "intermediate-ca",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cli.SignIntermediateCA(
			kmsKey,
			convertParentCertFlagsToCertificate(),
			convertChildCSRFlagsToCertificateRequest(),
			convertSubjectFlagsToName(),
			days,
			intermediateCAPathLen,
			intermediateCAPermittedDNSDomains,
			convertOutFlagsToFile(),
		)
	},
}

var signLeafCmd = &cobra.Command{
	Use:   "leaf",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cli.SignLeaf(
			kmsKey,
			convertParentCertFlagsToCertificate(),
			convertChildCSRFlagsToCertificateRequest(),
			convertSubjectFlagsToName(),
			days,
			leafDNSNames,
			leafIPAddresses,
			leafIsServer,
			leafIsClient,
			convertOutFlagsToFile(),
		)
	},
}

var (
	parentCertPath string
	childCSRPath   string

	intermediateCAPathLen             int
	intermediateCAPermittedDNSDomains []string

	leafDNSNames    []string
	leafIPAddresses []net.IP
	leafIsServer    bool
	leafIsClient    bool
)

func init() {
	addKeyFlags(signIntermediateCACmd)
	addKeyFlags(signLeafCmd)

	addParentCertFlags(signIntermediateCACmd)
	addParentCertFlags(signLeafCmd)

	addChildCSRFlags(signIntermediateCACmd)
	addChildCSRFlags(signLeafCmd)

	addSubjectFlags(signIntermediateCACmd)
	addSubjectFlags(signLeafCmd)

	addDaysFlags(signIntermediateCACmd)
	addDaysFlags(signLeafCmd)

	addOutFlags(signIntermediateCACmd)
	addOutFlags(signLeafCmd)

	// 'sign intermediate-ca' only flags
	signIntermediateCACmd.Flags().IntVar(
		&intermediateCAPathLen, "path-len", 0, "number of intermediate CAs allowed under this CA",
	)

	signIntermediateCACmd.Flags().StringSliceVar(
		&intermediateCAPermittedDNSDomains,
		"permitted-dns-domains",
		[]string{},
		"permitted DNS names for x509 Name Constraints extension",
	)

	// 'sign leaf' only flags
	signLeafCmd.Flags().StringSliceVar(
		&leafDNSNames,
		"dns-names",
		[]string{},
		"DNS names for x509 Subject Alternative Names extension",
	)

	signLeafCmd.Flags().IPSliceVar(
		&leafIPAddresses,
		"ip-addresses",
		[]net.IP{},
		"IP addresses for x509 Subject Alternative Names extension",
	)

	signLeafCmd.Flags().BoolVar(
		&leafIsServer,
		"server",
		false,
		"sign as a server cert",
	)

	signLeafCmd.Flags().BoolVar(
		&leafIsClient,
		"client",
		false,
		"sign as a client certificate",
	)

	signCmd.AddCommand(signIntermediateCACmd)
	signCmd.AddCommand(signLeafCmd)
}

func addParentCertFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&parentCertPath, "parent-cert", "", "parent certificate path")
	cmd.MarkFlagRequired("parent-cert")
}

func convertParentCertFlagsToCertificate() *x509.Certificate {
	parentCertBytes, err := ioutil.ReadFile(parentCertPath)

	if err != nil {
		panic(err)
	}

	parentCertBlock, _ := pem.Decode(parentCertBytes)

	if parentCertBlock == nil || parentCertBlock.Type != "CERTIFICATE" {
		panic("Failed to decode PEM-formatted parent certificate")
	}

	parentCert, err := x509.ParseCertificate(parentCertBlock.Bytes)

	if err != nil {
		panic(err)
	}

	return parentCert
}

func addChildCSRFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&childCSRPath, "child-csr", "", "child CSR path")
	cmd.MarkFlagRequired("child-csr")
}

func convertChildCSRFlagsToCertificateRequest() *x509.CertificateRequest {
	childCSRBytes, err := ioutil.ReadFile(childCSRPath)

	if err != nil {
		panic(err)
	}

	childCSRBlock, _ := pem.Decode(childCSRBytes)

	if childCSRBlock == nil || childCSRBlock.Type != "CERTIFICATE REQUEST" {
		panic("Failed to decode PEM-formatted child certificate request")
	}

	childCSR, err := x509.ParseCertificateRequest(childCSRBlock.Bytes)

	if err != nil {
		panic(err)
	}

	return childCSR
}
