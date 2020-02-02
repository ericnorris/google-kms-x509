package csr

import (
	"context"
	"crypto"
	"crypto/x509"
	//"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type GoogleKMSSigner struct {
	client    *cloudkms.KeyManagementClient
	key       *kmspb.CryptoKeyVersion
	publicKey crypto.PublicKey
}

func NewGoogleKMSSigner(client *cloudkms.KeyManagementClient, key *kmspb.CryptoKeyVersion) (*GoogleKMSSigner, error) {
	ctx := context.Background()

	publicKeyResponse, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: key.Name,
	})

	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode([]byte(publicKeyResponse.GetPem()))

	if pemBlock == nil {
		return nil, fmt.Errorf("no pem data in GetPublicKey() response")
	}

	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)

	if err != nil {
		return nil, err
	}

	signer := &GoogleKMSSigner{
		client,
		key,
		publicKey,
	}

	return signer, nil
}

func (signer *GoogleKMSSigner) Public() crypto.PublicKey {
	return signer.publicKey
}

func (signer *GoogleKMSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	req := &kmspb.AsymmetricSignRequest{
		Name: signer.key.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: []byte(digest),
			},
		},
	}

	ctx := context.Background()

	signatureResponse, err := signer.client.AsymmetricSign(ctx, req)

	if err != nil {
		return nil, err
	}

	return signatureResponse.Signature, nil
}
