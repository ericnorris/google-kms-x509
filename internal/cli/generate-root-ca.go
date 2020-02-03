package cli

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"github.com/ericnorris/google-kms-x509/kmssign"
)

func GenerateRootCA(kmsKey string, subject pkix.Name, days int) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)

	if err != nil {
		panic(err)
	}

	kmsSigner, err := kmssign.NewGoogleKMSSigner(ctx, client, kmsKey)

	if err != nil {
		panic(err)
	}

	now := time.Now()

	rootCertificateTemplate := &x509.Certificate{
		Subject:               subject,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, days),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCRLSign |
			x509.KeyUsageCertSign,
	}

	certificateBytes, err := kmsSigner.CreateSelfSignedCertificate(rootCertificateTemplate)

	if err != nil {
		panic(err)
	}

	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes})

	fmt.Println(string(certificate))
}
