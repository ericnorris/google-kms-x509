package cli

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"time"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"github.com/ericnorris/google-kms-x509/kmssign"
)

func SignLeaf(
	kmsKey string,
	generateComment bool,
	parentCert *x509.Certificate,
	childCSR *x509.CertificateRequest,
	subject pkix.Name,
	days int,
	dnsNames []string,
	ipAddresses []net.IP,
	isServer bool,
	isClient bool,
	crlDistributionPoints []string,
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

	if err := childCSR.CheckSignature(); err != nil {
		panic(err)
	}

	leafCertificateTemplate := &x509.Certificate{
		Subject:               subject,
		BasicConstraintsValid: true,
		IsCA:                  false,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, days),

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	if isServer {
		leafCertificateTemplate.ExtKeyUsage = append(
			leafCertificateTemplate.ExtKeyUsage,
			x509.ExtKeyUsageServerAuth,
		)
	}

	if isClient {
		leafCertificateTemplate.ExtKeyUsage = append(
			leafCertificateTemplate.ExtKeyUsage,
			x509.ExtKeyUsageClientAuth,
		)
	}

	if len(crlDistributionPoints) > 0 {
		leafCertificateTemplate.CRLDistributionPoints = crlDistributionPoints
	}

	certificateBytes, err := kmsSigner.CreateCertificate(
		leafCertificateTemplate,
		childCSR.PublicKey,
		generateComment,
	)

	if err != nil {
		panic(err)
	}

	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes})
}
