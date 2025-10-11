package cmd

import (
	"fmt"

	"github.com/eeekcct/kreseal/pkg/kreseal"
	"github.com/spf13/cobra"
)

var (
	sealOutputFile string
)

var sealCmd = &cobra.Command{
	Use:   "seal <secret-file>",
	Short: "Seal a Kubernetes Secret to a SealedSecret",
	Long: `Seal converts a Kubernetes Secret to a SealedSecret using the cluster's sealing key.
The output is written to the specified file:

  kreseal seal secret.yaml -o sealedsecret.yaml

This allows you to seal secrets without kubeseal CLI.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		secretFile := args[0]

		// Load certificate
		cert, err := kreseal.NewCert(config.SecretsName, config.Namespace)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}

		// Create kreseal client with certificate
		client := kreseal.NewClient(log, cert)

		// Use ResealSecret to convert Secret to SealedSecret
		if err := client.ResealSecret(secretFile, sealOutputFile); err != nil {
			return fmt.Errorf("failed to seal secret: %w", err)
		}

		log.Debugf("Successfully sealed %s to %s", secretFile, sealOutputFile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sealCmd)
	sealCmd.Flags().StringVarP(&sealOutputFile, "output", "o", "", "Output file for the SealedSecret (required)")
	_ = sealCmd.MarkFlagRequired("output")
}
