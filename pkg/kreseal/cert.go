package kreseal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/eeekcct/kreseal/pkg/k8s"
)

const (
	sessionKeyBytes = 32 // AES-256
)

type Cert struct {
	PublicKey       *rsa.PublicKey
	PrivateKey      *rsa.PrivateKey
	SessionKeyBytes int
	SecretsName     string
	Namespace       string
}

// NewCert creates a new Cert instance
func NewCert(name, namespace string) (*Cert, error) {
	ctx := context.Background()
	client, err := k8s.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return NewCertWithClient(client, name, namespace)
}

// NewCertWithClient creates a new Cert instance with a custom client (testable)
func NewCertWithClient(client k8s.ClientInterface, name, namespace string) (*Cert, error) {
	pubKey, privKey, err := getCertFromClient(client, name, namespace)
	if err != nil {
		return nil, err
	}
	return &Cert{
		PublicKey:       pubKey,
		PrivateKey:      privKey,
		SessionKeyBytes: sessionKeyBytes,
		SecretsName:     name,
		Namespace:       namespace,
	}, nil
}

// depricated: use v1alpha1.SealedSecret.Unseal()
func (c *Cert) Decrypt(data string, label []byte) ([]byte, error) {
	value, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 string: %w", err)
	}

	if len(value) < 2 {
		return nil, fmt.Errorf("invalid encrypted data length")
	}

	rsaLen := int(binary.BigEndian.Uint16(value))
	if len(value) < rsaLen+2 {
		return nil, fmt.Errorf("invalid encrypted data length")
	}

	rsaCiphertext := value[2 : rsaLen+2]
	aesCiphertext := value[rsaLen+2:]

	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.PrivateKey, rsaCiphertext, label)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES GCM: %w", err)
	}

	zeroNonce := make([]byte, aed.NonceSize())

	decryptedData, err := aed.Open(nil, zeroNonce, aesCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES data: %w", err)
	}

	return decryptedData, nil
}

// deprecated: use v1alpha1.NewSealedSecret()
func (c *Cert) Encrypt(data []byte, label []byte) (string, error) {
	sessionKey := make([]byte, c.SessionKeyBytes)
	rnd := rand.Reader
	if _, err := io.ReadFull(rnd, sessionKey); err != nil {
		return "", fmt.Errorf("failed to generate session key: %w", err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create AES GCM: %w", err)
	}

	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rnd, c.PublicKey, sessionKey, label)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Prepend the length of the RSA-encrypted session key
	rsaLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rsaLen, uint16(len(encryptedData)))
	ciphertext := append(rsaLen, encryptedData...)

	zeroNonce := make([]byte, aed.NonceSize())

	aesCiphertext := aed.Seal(ciphertext, zeroNonce, data, nil)

	value := base64.StdEncoding.EncodeToString(aesCiphertext)

	return value, nil
}

// getCertFromClient retrieves certificate using provided client (testable)
func getCertFromClient(client k8s.ClientInterface, name, namespace string) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	secrets, err := client.GetSecretsNameOrLabel(namespace, name, k8s.SealedSecretKeySelector())
	if err != nil {
		return nil, nil, err
	}
	if len(secrets) == 0 {
		return nil, nil, fmt.Errorf("no Secret found with name %s in namespace %s", name, namespace)
	}
	// Sort secrets by creation timestamp to get the latest one
	k8s.SortSecretsByCreationTimestamp(secrets)
	secret := &secrets[len(secrets)-1] // Get the most recently created secret

	privKey, err := parsePrivateKey(secret.Data["tls.key"])
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := parsePublicKey(secret.Data["tls.crt"])
	if err != nil {
		return nil, nil, err
	}

	return pubKey, privKey, nil
}

func parsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parsePublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not of type RSA")
	}
	return pub, nil
}
