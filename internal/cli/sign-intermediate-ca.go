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

func SignIntermediateCA(
	kmsKey string,
	parentCert *x509.Certificate,
	childCSR *x509.CertificateRequest,
	subject pkix.Name,
	days int,
	pathLen int,
	permittedDNSDomains []string,
	out *os.File,
) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)

	if err != nil {
		panic(err)
	}

	kmsSigner, err := kmssign.NewGoogleKMSSignerWithCertificate(ctx, client, kmsKey, parentCert)

	if err != nil {
		panic(err)
	}

	now := time.Now()

	// TODO validate child CSR

	intermediateCertificateTemplate := &x509.Certificate{
		Subject:               subject,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        true,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, days),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCRLSign |
			x509.KeyUsageCertSign,
	}

	if len(permittedDNSDomains) > 0 {
		intermediateCertificateTemplate.PermittedDNSDomainsCritical = true
		intermediateCertificateTemplate.PermittedDNSDomains = permittedDNSDomains
	}

	certificateBytes, err := kmsSigner.CreateCertificate(
		intermediateCertificateTemplate,
		childCSR.PublicKey,
	)

	if err != nil {
		panic(err)
	}

	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes})
}
