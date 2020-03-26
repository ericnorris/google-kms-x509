package cli

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"github.com/ericnorris/google-kms-x509/kmssign"
)

func GenerateRootCA(
	kmsKey string,
	generateComment bool,
	subject pkix.Name,
	days int,
	out *os.File,
) {
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

	certificateBytes, err := kmsSigner.CreateSelfSignedCertificate(
		rootCertificateTemplate,
		generateComment,
	)

	if err != nil {
		panic(err)
	}

	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes})
}
