package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandCompatibility(t *testing.T) {
	for _, name := range []string{"create", "seal", "version"} {
		command, _, err := rootCmd.Find([]string{name})
		require.NoError(t, err)
		assert.Equal(t, name, command.Name())
	}
	require.NoError(t, rootCmd.Args(rootCmd, []string{"existing.yaml"}))
	require.NoError(t, sealCmd.Args(sealCmd, []string{"plain.yaml"}))
	require.NoError(t, createCmd.Args(createCmd, []string{"new.yaml"}))
	require.Error(t, createCmd.Args(createCmd, nil))
	require.Error(t, createCmd.Args(createCmd, []string{"one.yaml", "two.yaml"}))
	assert.Nil(t, createCmd.Flags().Lookup("output"))
	assert.Nil(t, createCmd.Flags().ShorthandLookup("o"))
	require.NotNil(t, sealCmd.Flags().Lookup("output"))
	assert.Equal(t, "o", sealCmd.Flags().Lookup("output").Shorthand)
	require.Error(t, sealCmd.ValidateRequiredFlags())
	assert.Equal(t, "kube-system", rootCmd.PersistentFlags().Lookup("namespace").DefValue)
	assert.Nil(t, createCmd.Flags().Lookup("type"))
}
