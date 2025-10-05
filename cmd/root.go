/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/eeekcct/kreseal/pkg/kreseal"
	"github.com/eeekcct/kreseal/pkg/logger"
	"github.com/spf13/cobra"
)

var debug bool
var secretsName string
var namespace string
var log *logger.Logger

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "kreseal",
	Short: "Edit and reseal Kubernetes SealedSecrets",
	Long:  `kreseal makes editing SealedSecrets easier by unsealing, editing, and resealing automatically.`,
	Args:  cobra.MaximumNArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log = logger.New(debug) // Initialize logger
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		orgFile := args[0]

		// Load certificate
		cert, err := kreseal.NewCert(secretsName, namespace)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}

		// Create kreseal client with certificate
		client := kreseal.NewClient(log, cert)

		// Create temporary file
		tempFile := kreseal.NewTempFile(log)
		if err := tempFile.CreateTempFile(orgFile); err != nil {
			return err
		}
		defer func() {
			tempFile.Cleanup()
			_ = log.Close()
		}()

		// Unseal SealedSecret to temporary file
		if err := client.UnsealSealedSecret(orgFile, tempFile.Path); err != nil {
			return err
		}

		// Edit the temporary file
		if err := client.EditFile(tempFile.Path); err != nil {
			return err
		}

		// Reseal the edited Secret
		if err := client.ResealSecret(tempFile.Path, orgFile); err != nil {
			return err
		}

		log.Debugf("Successfully resealed and saved to %s", orgFile)
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.kreseal.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")
	rootCmd.PersistentFlags().StringVarP(&secretsName, "secrets-name", "s", "sealed-secrets", "Name of the secrets")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "Namespace of the secrets")
}
