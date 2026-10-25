package cmd

import (
	"github.com/eeekcct/kreseal/pkg/kreseal"
	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create <output-file>",
	Short: "Create a Secret in your editor and save a SealedSecret file",
	Long: `Create opens a plain Secret template in $EDITOR (default: vi).
Edit its name, namespace and data, then save and exit to seal it.
The initial target namespace is default; --namespace selects controller keys.
An unchanged template cancels creation. Existing output files are never overwritten.

  kreseal create my-secret.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := kreseal.NewClient(log, nil)
		return client.CreateSecret(args[0], func() (*kreseal.Cert, error) {
			return kreseal.NewCert(config.SecretsName, config.Namespace)
		})
	},
}

func init() {
	rootCmd.AddCommand(createCmd)
}
