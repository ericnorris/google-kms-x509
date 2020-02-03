package kmssign

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

var nsCommentOID = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}

type GoogleKMSSigner struct {
	// not ideal, but crypto.Signer doesn't have an obvious way to pass in a context.
	// see https://github.com/golang/go/issues/28427
	ctx context.Context

	client             *cloudkms.KeyManagementClient
	keyVersion         *kmspb.CryptoKeyVersion
	signatureAlgorithm x509.SignatureAlgorithm
	hashFunction       crypto.Hash
	publicKey          crypto.PublicKey
	certificate        *x509.Certificate
}

func NewGoogleKMSSigner(
	ctx context.Context,
	client *cloudkms.KeyManagementClient,
	keyName string,
) (*GoogleKMSSigner, error) {
	keyVersion, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: keyName,
	})

	if err != nil {
		return nil, fmt.Errorf("Could not get key version information: %w", err)
	}

	signatureAlgorithm, hashFunction, err := determineSignatureAlgorithm(keyVersion)

	if err != nil {
		return nil, err
	}

	publicKey, err := getPublicKey(ctx, client, keyVersion)

	if err != nil {
		return nil, err
	}

	signer := &GoogleKMSSigner{
		ctx,
		client,
		keyVersion,
		signatureAlgorithm,
		hashFunction,
		publicKey,
		nil,
	}

	return signer, nil
}

func NewGoogleKMSSignerWithCertificate(
	ctx context.Context,
	client *cloudkms.KeyManagementClient,
	keyName string,
	certificate *x509.Certificate,
) (*GoogleKMSSigner, error) {
	signer, err := NewGoogleKMSSigner(ctx, client, keyName)

	if err != nil {
		return nil, err
	}

	signer.certificate = certificate

	return signer, nil
}

func (signer *GoogleKMSSigner) CreateCertificate(
	template *x509.Certificate,
	signee crypto.PublicKey,
) (cert []byte, err error) {
	if signer.certificate == nil {
		return nil, fmt.Errorf("Cannot sign child certificate without a parent")
	}

	if signer.certificate.IsCA == false {
		return nil, fmt.Errorf("Cannot sign certificate with a non-CA certificate")
	}

	subjectKeyId, err := computeSubjectKeyIdentifier(signee)

	if err != nil {
		return nil, fmt.Errorf("Could not compute subject key identifier: %w", err)
	}

	serialNumber, err := generateSerialNumber()

	if err != nil {
		return nil, fmt.Errorf("Could not generate serial number: %w", err)
	}

	template.SignatureAlgorithm = signer.signatureAlgorithm
	template.SubjectKeyId = subjectKeyId
	template.SerialNumber = serialNumber

	template.ExtraExtensions = append(
		template.ExtraExtensions,
		pkix.Extension{
			Id:    nsCommentOID,
			Value: []byte(fmt.Sprintf("Signed with Google KMS key: %s", signer.keyVersion.Name)),
		},
	)

	rawCertificate, err := x509.CreateCertificate(
		rand.Reader,
		template,
		signer.certificate,
		signee,
		signer,
	)

	if err != nil {
		return nil, fmt.Errorf("Could not create certificate: %w", err)
	}

	return rawCertificate, nil
}

func (signer *GoogleKMSSigner) CreateSelfSignedCertificate(
	template *x509.Certificate,
) (cert []byte, err error) {
	if signer.certificate == nil {
		return nil, fmt.Errorf("Cannot create self signed certificate with a parent")
	}

	signer.certificate = template

	rawCertificate, err := signer.CreateCertificate(template, signer.publicKey)

	if err != nil {
		signer.certificate = nil
	}

	return rawCertificate, err
}

func (signer *GoogleKMSSigner) CreateCertificateRequest(
	template *x509.CertificateRequest,
) (cert []byte, err error) {
	template.SignatureAlgorithm = signer.signatureAlgorithm

	rawCertificateRequest, err := x509.CreateCertificateRequest(
		rand.Reader,
		template,
		signer,
	)

	if err != nil {
		return nil, fmt.Errorf("Could not create certificate request: %w", err)
	}

	return rawCertificateRequest, nil
}

func (signer *GoogleKMSSigner) Public() crypto.PublicKey {
	return signer.publicKey
}

func (signer *GoogleKMSSigner) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	if opts.HashFunc() != signer.hashFunction {
		return nil, fmt.Errorf(
			"Unexpected hash function, got: %s, wanted %s", opts.HashFunc(), signer.hashFunction,
		)
	}

	var kmspbDigest kmspb.Digest

	switch opts.HashFunc() {
	case crypto.SHA256:
		kmspbDigest = kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}

	case crypto.SHA384:
		kmspbDigest = kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}}

	case crypto.SHA512:
		kmspbDigest = kmspb.Digest{Digest: &kmspb.Digest_Sha512{Sha512: digest}}

	default:
		return nil, fmt.Errorf("Cannot convert hash function %s to KMS digest", opts.HashFunc())
	}

	signRequest := &kmspb.AsymmetricSignRequest{
		Name:   signer.keyVersion.Name,
		Digest: &kmspbDigest,
	}

	signResponse, err := signer.client.AsymmetricSign(signer.ctx, signRequest)

	if err != nil {
		return nil, fmt.Errorf("Error in AsymmetricSign(): %w", err)
	}

	return signResponse.Signature, nil
}

func determineSignatureAlgorithm(
	keyVersion *kmspb.CryptoKeyVersion,
) (x509.SignatureAlgorithm, crypto.Hash, error) {
	switch keyVersion.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		fallthrough
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256:
		fallthrough
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		return x509.SHA256WithRSA, crypto.SHA256, nil

	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return x509.SHA512WithRSA, crypto.SHA512, nil

	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return x509.ECDSAWithSHA256, crypto.SHA256, nil

	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return x509.ECDSAWithSHA384, crypto.SHA384, nil

	default:
		return x509.UnknownSignatureAlgorithm, 0, fmt.Errorf(
			"Key version has unsupported algorithm: %s",
			keyVersion.Algorithm,
		)
	}
}

func getPublicKey(
	ctx context.Context,
	client *cloudkms.KeyManagementClient,
	keyVersion *kmspb.CryptoKeyVersion,
) (crypto.PublicKey, error) {
	publicKeyResponse, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyVersion.Name,
	})

	if err != nil {
		return nil, fmt.Errorf("Error in GetPublicKey(): %w", err)
	}

	pemBlock, _ := pem.Decode([]byte(publicKeyResponse.GetPem()))

	if pemBlock == nil {
		return nil, fmt.Errorf("Invalid PEM data in GetPublicKey() response")
	}

	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)

	if err != nil {
		return nil, fmt.Errorf("Could not parse public key: %w", err)
	}

	return publicKey, nil
}

// https://tools.ietf.org/html/rfc3280#section-4.2.1.2
func computeSubjectKeyIdentifier(subjectPublicKey crypto.PublicKey) ([]byte, error) {
	derEncodedPublicKey, err := x509.MarshalPKIXPublicKey(subjectPublicKey)

	if err != nil {
		return nil, err
	}

	asn1PublicKey := struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{}

	if _, err := asn1.Unmarshal(derEncodedPublicKey, &asn1PublicKey); err != nil {
		return nil, err
	}

	subjectKeyIdentifier := sha1.Sum(asn1PublicKey.SubjectPublicKey.Bytes)

	return subjectKeyIdentifier[:], nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberMax := new(big.Int)

	serialNumberMax.Exp(big.NewInt(2), big.NewInt(64), nil)
	serialNumberMax.Sub(serialNumberMax, big.NewInt(1))

	return rand.Int(rand.Reader, serialNumberMax)
}
