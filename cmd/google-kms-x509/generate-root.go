package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"github.com/ericnorris/google-kms-x509/kmssign"
	"github.com/spf13/cobra"
)

// TODO move this to utility file
// var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func init() {
	var key string
	var commonName string
	var country string
	var province string
	var locality string
	var organization string
	var organizationalUnit string
	var emailAddress string
	var days int

	var generateRootCmd = &cobra.Command{
		Use:   "generate-root",
		Short: "",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			subject := pkix.Name{
				CommonName: commonName,
			}

			if country != "" {
				subject.Country = []string{country}
			}

			if province != "" {
				subject.Province = []string{province}
			}

			if locality != "" {
				subject.Locality = []string{locality}
			}

			if organization != "" {
				subject.Organization = []string{organization}
			}

			if organizationalUnit != "" {
				subject.OrganizationalUnit = []string{organizationalUnit}
			}

			if emailAddress != "" {
				subject.ExtraNames = []pkix.AttributeTypeAndValue{
					{
						Type:  oidEmailAddress,
						Value: emailAddress,
					},
				}
			}

			ctx := context.Background()
			client, err := cloudkms.NewKeyManagementClient(ctx)

			if err != nil {
				panic(err)
			}

			signer, err := kmssign.NewGoogleKMSSigner(ctx, client, key)

			if err != nil {
				panic(err)
			}

			now := time.Now()

			serialNumberMax := new(big.Int)

			serialNumberMax.Exp(big.NewInt(2), big.NewInt(64), nil)
			serialNumberMax.Sub(serialNumberMax, big.NewInt(1))

			serialNumber, err := rand.Int(rand.Reader, serialNumberMax)

			if err != nil {
				panic(err)
			}

			template := &x509.Certificate{
				Subject:        subject,
				IsCA:           true,
				MaxPathLen:     0,
				MaxPathLenZero: false,
				NotBefore:      now,
				NotAfter:       now.AddDate(0, 0, days),

				KeyUsage: x509.KeyUsageDigitalSignature |
					x509.KeyUsageCRLSign |
					x509.KeyUsageCertSign,

				SerialNumber: serialNumber,
			}

			rawCertificate, err := signer.CreateSelfSignedCertificate(template)

			if err != nil {
				panic(err)
			}

			rootCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawCertificate})

			fmt.Println(string(rootCA))
		},
	}

	generateRootCmd.Flags().StringVarP(
		&key, "key", "k", "", "Google KMS key to use for signature",
	)

	generateRootCmd.Flags().StringVarP(
		&commonName, "common-name", "", "", "Common Name to use for CA",
	)

	generateRootCmd.Flags().StringVarP(
		&country, "country", "", "", "Country to use for CA",
	)

	generateRootCmd.Flags().StringVarP(
		&province, "province", "", "", "Province to use for CA",
	)

	generateRootCmd.Flags().StringVarP(
		&locality, "locality", "", "", "Locality to use for CA",
	)

	generateRootCmd.Flags().StringVarP(
		&organization, "organization", "", "", "Organization to use for CA",
	)

	generateRootCmd.Flags().StringVarP(
		&organizationalUnit, "organizationalUnit", "", "", "Organizational Unit to use for CA",
	)

	generateRootCmd.Flags().StringVarP(
		&emailAddress, "emailAddress", "", "", "Email Address to use for CA",
	)

	generateRootCmd.Flags().IntVarP(
		&days, "days", "", 0, "Number of days the CA is valid",
	)

	generateRootCmd.MarkFlagRequired("key")
	generateRootCmd.MarkFlagRequired("common-name")
	generateRootCmd.MarkFlagRequired("days")

	rootCmd.AddCommand(generateRootCmd)
}
