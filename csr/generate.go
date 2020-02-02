package csr

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"github.com/ericnorris/google-kms-x509/kmssign"
)

func Generate(keyName string, subject pkix.Name) (string, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)

	if err != nil {
		return "", err
	}

	signer, err := kmssign.NewGoogleKMSSigner(ctx, client, keyName)

	if err != nil {
		return "", err
	}

	template := &x509.CertificateRequest{
		Subject: subject,
	}

	rawCSR, err := signer.CreateCertificateRequest(template)

	if err != nil {
		return "", err
	}

	pemCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: rawCSR})

	return string(pemCSR), nil
}
