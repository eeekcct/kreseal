package kreseal

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/eeekcct/kreseal/pkg/k8s"
	"github.com/eeekcct/kreseal/pkg/logger"
	"sigs.k8s.io/yaml"
)

// Client represents a kreseal client with configuration
type Client struct {
	Cert   *Cert
	Logger *logger.Logger
}

// NewClient creates a new kreseal client with an existing certificate
func NewClient(logger *logger.Logger, cert *Cert) *Client {
	return &Client{
		Cert:   cert,
		Logger: logger,
	}
}

// UnsealSealedSecret unseals a SealedSecret to a temporary file
func (c *Client) UnsealSealedSecret(inputFile, outputFile string) error {
	c.Logger.Debugf("Unsealing %s to %s", inputFile, outputFile)

	input, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	sealedSecrets, err := k8s.ReadSealedSecrets(input)
	if err != nil {
		return fmt.Errorf("failed to read SealedSecrets from input: %w", err)
	}
	if len(sealedSecrets) == 0 {
		return fmt.Errorf("no SealedSecrets found in input")
	}

	var buf bytes.Buffer
	for _, ss := range sealedSecrets {
		label := k8s.GetEncryptionLabel(ss)
		data := ss.Spec.EncryptedData

		// Convert EncryptedData to Secret Data
		secretData := make(map[string][]byte)
		for k, v := range data {
			secretData[k], err = c.Cert.Decrypt(v, label)
			if err != nil {
				return fmt.Errorf("failed to decrypt data for key %s: %w", k, err)
			}
		}
		secret := k8s.NewSecret(secretData, ss.Spec.Template)

		// Write Secret to outputFile
		if err := c.marshalYAML(secret, &buf); err != nil {
			return fmt.Errorf("failed to marshal Secret to YAML: %w", err)
		}
	}

	if err := c.writeYAML(&buf, outputFile); err != nil {
		return fmt.Errorf("failed to write Secret to file: %w", err)
	}

	c.Logger.Debugf("Successfully unsealed %s to %s", inputFile, outputFile)
	return nil
}

// EditFile opens the specified file in an editor
func (c *Client) EditFile(filePath string) error {
	// Get editor from environment variable
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi" // Default editor
	}
	editorCmd := strings.Split(editor, " ")
	editorCmd = append(editorCmd, filePath)

	c.Logger.Debugf("Opening %s with editor: %s", filePath, editor)

	// Execute editor command
	cmd := exec.Command(editorCmd[0], editorCmd[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to edit %s with %s: %w", filePath, editor, err)
	}

	c.Logger.Debugf("Successfully edited %s", filePath)
	return nil
}

// ResealSecret reseals a Secret file to SealedSecret with backup and restore functionality
func (c *Client) ResealSecret(inputFile, outputFile string) error {
	// Check if outputFile exists for backup
	var backup string
	if _, err := os.Stat(outputFile); err == nil {
		backup = outputFile + ".bak"
		if err := os.Rename(outputFile, backup); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
		c.Logger.Debugf("Created backup: %s", backup)
	}

	c.Logger.Debugf("Resealing %s to %s", inputFile, outputFile)

	// Convert Secret to SealedSecret and write to file
	if err := c.sealSecretFile(inputFile, outputFile); err != nil {
		if backup != "" {
			_ = os.Rename(backup, outputFile)
		}
		return err
	}

	// Remove backup on success
	if backup != "" {
		if err := os.Remove(backup); err != nil {
			c.Logger.Warnf("Failed to remove backup file %s: %v", backup, err)
		} else {
			c.Logger.Debugf("Removed backup: %s", backup)
		}
	}

	c.Logger.Debugf("Successfully resealed %s to %s", inputFile, outputFile)
	return nil
}

// sealSecretFile converts a Secret file to SealedSecret and writes to output file
func (c *Client) sealSecretFile(inputFile, outputFile string) error {
	input, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	secrets, err := k8s.ReadSecrets(input)
	if err != nil {
		return fmt.Errorf("failed to read Secrets from input: %w", err)
	}
	if len(secrets) == 0 {
		return fmt.Errorf("no Secrets found in input")
	}

	var buf bytes.Buffer
	for _, secret := range secrets {
		// Set namespace from Cert if Secret doesn't have one
		if secret.Namespace == "" {
			secret.Namespace = c.Cert.Namespace
		}

		label := k8s.GetEncryptionLabelFromSecret(secret)
		secretData := secret.Data

		// Convert Secret Data to EncryptedData
		encryptedData := make(map[string]string)
		for k, v := range secretData {
			encData, err := c.Cert.Encrypt(v, label)
			if err != nil {
				return fmt.Errorf("failed to encrypt data for key %s: %w", k, err)
			}
			encryptedData[k] = encData
		}

		// Create new SealedSecret with updated encryptedData and template
		ss := k8s.NewSealedSecret(encryptedData, secret)

		// Marshal SealedSecret to YAML
		if err := c.marshalYAML(ss, &buf); err != nil {
			return fmt.Errorf("failed to marshal SealedSecret to YAML: %w", err)
		}
	}

	// Write to output file
	if err := c.writeYAML(&buf, outputFile); err != nil {
		return err
	}

	return nil
}

func (c *Client) marshalYAML(data interface{}, buf *bytes.Buffer) error {
	b, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	buf.WriteString("---\n")
	buf.Write(b)
	return nil
}

func (c *Client) writeYAML(data *bytes.Buffer, outputFile string) error {
	if err := os.WriteFile(outputFile, data.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write YAML to file: %w", err)
	}
	return nil
}
