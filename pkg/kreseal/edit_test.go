package kreseal

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eeekcct/kreseal/pkg/k8s"
	"github.com/eeekcct/kreseal/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Run a child test process as the editor using synthetic contents only.
func TestEditEditorHelper(t *testing.T) {
	mode := os.Getenv("KRESEAL_EDIT_TEST_MODE")
	if mode == "" {
		return
	}
	path := os.Args[len(os.Args)-1]
	input, err := os.ReadFile(path)
	if err != nil {
		os.Exit(10)
	}
	switch mode {
	case "changed", "failure":
		input = bytes.ReplaceAll(input, []byte("c3ludGhldGljLW9sZA=="), []byte("c3ludGhldGljLW5ldw=="))
	case "formatting":
		input = append(input, '\n')
	case "removed":
		if err := os.Remove(path); err != nil {
			os.Exit(11)
		}
		os.Exit(0)
	case "directory":
		if err := os.Remove(path); err != nil {
			os.Exit(13)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			os.Exit(14)
		}
		os.Exit(0)
	}
	// Also test an editor that rewrites identical contents when saving.
	if err := os.WriteFile(path, input, 0600); err != nil {
		os.Exit(12)
	}
	if mode == "failure" {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestClient_EditAndResealSecret(t *testing.T) {
	log := logger.New(false)
	defer func() { _ = log.Close() }()
	cert := createTestCert(t)
	for _, tt := range []struct {
		mode, wantError, value string
		changed                bool
	}{
		{mode: "unchanged", value: "synthetic-old"},
		{mode: "changed", value: "synthetic-new", changed: true},
		{mode: "formatting", value: "synthetic-old", changed: true},
		{mode: "failure", wantError: "failed to edit", value: "synthetic-old"},
		{mode: "removed", wantError: "failed to read Secret after editing", value: "synthetic-old"},
		{mode: "directory", wantError: "failed to read Secret after editing", value: "synthetic-old"},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			dir := t.TempDir()
			plain := filepath.Join(dir, "plain.yaml")
			sealed := filepath.Join(dir, "sealed.yaml")
			require.NoError(t, os.WriteFile(plain, []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: test-secret\n  namespace: default\ndata:\n  value: c3ludGhldGljLW9sZA==\n"), 0600))
			client := NewClient(log, cert)
			require.NoError(t, client.ResealSecret(plain, sealed))
			original, err := os.ReadFile(sealed)
			require.NoError(t, err)
			// Preserve noncanonical formatting as well as the exact ciphertext.
			original = append([]byte("# preserve this comment\n"), original...)
			require.NoError(t, os.WriteFile(sealed, original, 0600))
			oldTime := time.Unix(1000000000, 0)
			require.NoError(t, os.Chtimes(sealed, oldTime, oldTime))
			before, err := os.Stat(sealed)
			require.NoError(t, err)
			require.NoError(t, client.UnsealSealedSecret(sealed, plain))
			executable, err := os.Executable()
			require.NoError(t, err)
			t.Setenv("EDITOR", executable+" -test.run=^TestEditEditorHelper$ --")
			t.Setenv("KRESEAL_EDIT_TEST_MODE", tt.mode)
			if !tt.changed {
				// Skipped paths must never encrypt.
				client.Cert = nil
			}
			err = client.EditAndResealSecret(plain, sealed)
			if tt.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantError)
			}
			actual, err := os.ReadFile(sealed)
			require.NoError(t, err)
			after, err := os.Stat(sealed)
			require.NoError(t, err)
			if tt.changed {
				assert.NotEqual(t, original, actual)
			} else {
				assert.Equal(t, original, actual)
				assert.Equal(t, before.ModTime(), after.ModTime())
				assert.Equal(t, before.Mode(), after.Mode())
				assert.True(t, os.SameFile(before, after), "original file must not be replaced")
			}
			_, err = os.Stat(sealed + ".bak")
			require.True(t, os.IsNotExist(err))
			secrets, err := k8s.ReadSealedSecrets(actual)
			require.NoError(t, err)
			require.Len(t, secrets, 1)
			value, err := cert.Decrypt(secrets[0].Spec.EncryptedData["value"], k8s.GetEncryptionLabel(secrets[0]))
			require.NoError(t, err)
			assert.Equal(t, tt.value, string(value))
		})
	}
}

func TestSecretFileDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.yaml")
	for _, input := range [][]byte{nil, []byte("synthetic"), []byte("synthetic\n")} {
		require.NoError(t, os.WriteFile(path, input, 0600))
		digest, err := secretFileDigest(path)
		require.NoError(t, err)
		assert.Equal(t, sha256.Sum256(input), digest)
	}
	// Exercise multiple streaming reads without a large plaintext allocation in the test.
	file, err := os.Create(path)
	require.NoError(t, err)
	chunk := bytes.Repeat([]byte("synthetic-data\n"), 4096)
	expected := sha256.New()
	for range 128 {
		_, err := file.Write(chunk)
		require.NoError(t, err)
		_, err = expected.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, file.Close())
	digest, err := secretFileDigest(path)
	require.NoError(t, err)
	assert.Equal(t, expected.Sum(nil), digest[:])
	for _, unreadable := range []string{filepath.Join(dir, "missing"), dir} {
		_, err := secretFileDigest(unreadable)
		require.Error(t, err, "open/read failures must not produce a usable digest")
	}
}

func TestClient_EditAndResealSecretMissingInput(t *testing.T) {
	log := logger.New(false)
	defer func() { _ = log.Close() }()
	dir := t.TempDir()
	sealed := filepath.Join(dir, "sealed.yaml")
	require.NoError(t, os.WriteFile(sealed, []byte("original"), 0600))
	err := NewClient(log, nil).EditAndResealSecret(filepath.Join(dir, "missing.yaml"), sealed)
	require.ErrorContains(t, err, "failed to read Secret before editing")
	actual, err := os.ReadFile(sealed)
	require.NoError(t, err)
	assert.Equal(t, "original", string(actual))
}

func TestClient_ExplicitResealUnchangedSecret(t *testing.T) {
	log := logger.New(false)
	defer func() { _ = log.Close() }()
	client := NewClient(log, createTestCert(t))
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.yaml")
	sealed := filepath.Join(dir, "sealed.yaml")
	require.NoError(t, os.WriteFile(plain, []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: test-secret\n  namespace: default\ndata:\n  value: c3ludGhldGljLW9sZA==\n"), 0600))
	require.NoError(t, client.ResealSecret(plain, sealed))
	original, err := os.ReadFile(sealed)
	require.NoError(t, err)
	require.NoError(t, client.ResealSecret(plain, sealed))
	actual, err := os.ReadFile(sealed)
	require.NoError(t, err)
	assert.NotEqual(t, original, actual, "explicit resealing must generate new ciphertext")
	secrets, err := k8s.ReadSealedSecrets(actual)
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	value, err := client.Cert.Decrypt(secrets[0].Spec.EncryptedData["value"], k8s.GetEncryptionLabel(secrets[0]))
	require.NoError(t, err)
	assert.Equal(t, "synthetic-old", string(value))
}
