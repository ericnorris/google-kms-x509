package csr

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"crypto/rand"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func Generate(keyName string, subject pkix.Name) (string, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)

	if err != nil {
		return "", err
	}

	key, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: keyName,
	})

	if err != nil {
		return "", err
	}

	var signatureAlgorithm x509.SignatureAlgorithm

	signatureAlgorithm = x509.ECDSAWithSHA256

	switch key.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		fallthrough
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256:
		fallthrough
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		signatureAlgorithm = x509.SHA256WithRSA

	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		signatureAlgorithm = x509.SHA512WithRSA

	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		signatureAlgorithm = x509.ECDSAWithSHA256

	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		signatureAlgorithm = x509.ECDSAWithSHA384
	}

	signer, err := NewGoogleKMSSigner(client, key)

	if err != nil {
		return "", err
	}

	template := &x509.CertificateRequest{
		Subject: subject,
		SignatureAlgorithm: signatureAlgorithm,
	}

	rawCSR, err := x509.CreateCertificateRequest(rand.Reader, template, signer)

	if err != nil {
		return "", err
	}

	pemCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: rawCSR})

	return string(pemCSR), nil
}
