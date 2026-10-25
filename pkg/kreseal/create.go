package kreseal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"
)

const secretTemplate = `apiVersion: v1
kind: Secret
metadata:
  name: ""
  namespace: default
type: Opaque
stringData: {}
`

// CreateSecret edits a new Secret and saves its sealed form without overwriting a file.
// The certificate is loaded only after the editor succeeds and the Secret is valid.
func (c *Client) CreateSecret(outputFile string, loadCert func() (*Cert, error)) error {
	if outputFile == "" {
		return fmt.Errorf("output file is required")
	}
	if _, err := os.Lstat(outputFile); err == nil {
		return fmt.Errorf("output file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to check output file: %w", err)
	}

	// A private directory also contains editor backup/swap files for cleanup.
	dir, err := os.MkdirTemp("", "kreseal-create-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			c.Logger.Warnf("Failed to remove temporary directory: %v", err)
		}
	}()
	plaintext := filepath.Join(dir, "secret.yaml")
	if err := os.WriteFile(plaintext, []byte(secretTemplate), 0600); err != nil {
		return fmt.Errorf("failed to write template: %w", err)
	}
	if err := c.EditFile(plaintext); err != nil {
		return err
	}
	edited, err := os.ReadFile(plaintext)
	if err != nil {
		return fmt.Errorf("failed to read edited Secret: %w", err)
	}
	if bytes.Equal(edited, []byte(secretTemplate)) {
		return nil
	}
	if err := validateCreatedSecret(edited); err != nil {
		return err
	}
	cert, err := loadCert()
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	sealed := filepath.Join(dir, "sealed.yaml")
	if err := NewClient(c.Logger, cert).sealSecretFile(plaintext, sealed); err != nil {
		return fmt.Errorf("failed to seal Secret")
	}
	content, err := os.ReadFile(sealed)
	if err != nil {
		return fmt.Errorf("failed to read sealed output: %w", err)
	}
	// O_EXCL protects against both existing files and files created during editing.
	out, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	_, writeErr := out.Write(content)
	closeErr := out.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(outputFile)
		return fmt.Errorf("failed to write sealed output: %w", err)
	}
	return nil
}

func validateCreatedSecret(input []byte) error {
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(input), 4096)
	var secret corev1.Secret
	// Decoder diagnostics can contain plaintext values, so do not return them.
	if err := decoder.Decode(&secret); err != nil {
		return fmt.Errorf("invalid Secret YAML")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected exactly one Secret YAML document")
	}
	// Reject duplicate mappings and misspelled fields instead of dropping values.
	if err := sigsyaml.UnmarshalStrict(input, &secret); err != nil {
		return fmt.Errorf("invalid Secret YAML")
	}
	if secret.APIVersion != "v1" || secret.Kind != "Secret" {
		return fmt.Errorf("expected apiVersion v1 and kind Secret")
	}
	if secret.Name == "" || len(validation.IsDNS1123Subdomain(secret.Name)) != 0 {
		return fmt.Errorf("metadata.name must be a valid nonempty Secret name")
	}
	if secret.Namespace == "" || len(validation.IsDNS1123Label(secret.Namespace)) != 0 {
		return fmt.Errorf("metadata.namespace must be a valid nonempty namespace")
	}
	return nil
}
