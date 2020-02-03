package cli

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"github.com/ericnorris/google-kms-x509/kmssign"
)

func GenerateCSR(kmsKey string, subject pkix.Name) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)

	if err != nil {
		panic(err)
	}

	kmsSigner, err := kmssign.NewGoogleKMSSigner(ctx, client, kmsKey)

	if err != nil {
		panic(err)
	}

	template := &x509.CertificateRequest{
		Subject: subject,
	}

	csrBytes, err := kmsSigner.CreateCertificateRequest(template)

	if err != nil {
		panic(err)
	}

	pemCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	fmt.Println(string(pemCSR))
}
