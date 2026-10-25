package kreseal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eeekcct/kreseal/pkg/k8s"
	"github.com/eeekcct/kreseal/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Use a child of the test binary as an editor, without a shell or real secrets.
func TestCreateEditorHelper(t *testing.T) {
	if os.Getenv("KRESEAL_TEST_EDITOR") != "1" {
		return
	}
	path := os.Args[len(os.Args)-1]
	input, err := os.ReadFile(path)
	if err != nil || string(input) != secretTemplate {
		os.Exit(10)
	}
	info, err := os.Stat(path)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		os.Exit(11)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil || (runtime.GOOS != "windows" && dirInfo.Mode().Perm() != 0700) {
		os.Exit(12)
	}
	if err := os.WriteFile(path+".bak", input, 0600); err != nil {
		os.Exit(13)
	}
	if os.Getenv("KRESEAL_TEST_FAIL") == "1" {
		os.Exit(1)
	}
	if race := os.Getenv("KRESEAL_TEST_RACE"); race != "" {
		if err := os.WriteFile(race, []byte("keep me"), 0600); err != nil {
			os.Exit(14)
		}
	}
	if replacement := os.Getenv("KRESEAL_TEST_CONTENT"); replacement != "" {
		if err := os.WriteFile(path, []byte(replacement), 0600); err != nil {
			os.Exit(15)
		}
	}
	os.Exit(0)
}

func TestCreateSecret(t *testing.T) {
	log := logger.New(false)
	defer func() { _ = log.Close() }()
	cert := createTestCert(t)
	cert.Namespace = "controller-system"
	valid := strings.Replace(secretTemplate, `name: ""`, "name: new-secret", 1)
	valid = strings.Replace(valid, "namespace: default", "namespace: apps", 1)
	valid = strings.Replace(valid, "stringData: {}", "data:\n  duplicate: b2xk\n  binary: AP8=\nstringData:\n  duplicate: synthetic-password\n  added: synthetic-value", 1)
	for _, tt := range []struct {
		name, content, wantError          string
		fail, existing, race, certFailure bool
		loads                             int
	}{
		{name: "success", content: valid, loads: 1},
		{name: "unchanged"},
		{name: "editor failure", fail: true, wantError: "failed to edit"},
		{name: "invalid yaml", content: "stringData: [synthetic-sensitive", wantError: "invalid Secret YAML"},
		{name: "invalid data", content: valid + "\nimmutable: synthetic-sensitive", wantError: "invalid Secret YAML"},
		{name: "duplicate keys", content: valid + "\nstringData: {}\n", wantError: "invalid Secret YAML"},
		{name: "unknown field", content: valid + "\nstringDatas: {}\n", wantError: "invalid Secret YAML"},
		{name: "empty name", content: secretTemplate + "\n", wantError: "metadata.name"},
		{name: "invalid name", content: strings.Replace(valid, "new-secret", "INVALID", 1), wantError: "metadata.name"},
		{name: "invalid namespace", content: strings.Replace(valid, "namespace: apps", "namespace: BAD", 1), wantError: "metadata.namespace"},
		{name: "empty namespace", content: strings.Replace(valid, "namespace: apps", `namespace: ""`, 1), wantError: "metadata.namespace"},
		{name: "wrong kind", content: strings.Replace(valid, "kind: Secret", "kind: ConfigMap", 1), wantError: "expected apiVersion"},
		{name: "multiple documents", content: valid + "---\nkind: ConfigMap\n", wantError: "exactly one"},
		{name: "existing output", existing: true, wantError: "already exists"},
		{name: "output race", content: valid, race: true, loads: 1, wantError: "failed to create output"},
		{name: "certificate failure", content: valid, certFailure: true, loads: 1, wantError: "failed to load certificate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tempDir := filepath.Join(dir, "temp")
			require.NoError(t, os.Mkdir(tempDir, 0700))
			t.Setenv("TMPDIR", tempDir)
			t.Setenv("TMP", tempDir)
			t.Setenv("TEMP", tempDir)
			executable, err := os.Executable()
			require.NoError(t, err)
			t.Setenv("EDITOR", executable+" -test.run=^TestCreateEditorHelper$ --")
			t.Setenv("KRESEAL_TEST_EDITOR", "1")
			t.Setenv("KRESEAL_TEST_CONTENT", tt.content)
			t.Setenv("KRESEAL_TEST_FAIL", "0")
			t.Setenv("KRESEAL_TEST_RACE", "")
			if tt.fail {
				t.Setenv("KRESEAL_TEST_FAIL", "1")
			}
			output := filepath.Join(dir, "sealed.yaml")
			if tt.existing {
				require.NoError(t, os.WriteFile(output, []byte("keep me"), 0600))
			}
			if tt.race {
				t.Setenv("KRESEAL_TEST_RACE", output)
			}
			loads := 0
			err = NewClient(log, nil).CreateSecret(output, func() (*Cert, error) {
				loads++
				if tt.certFailure {
					return nil, fmt.Errorf("synthetic certificate failure")
				}
				return cert, nil
			})
			assert.Equal(t, tt.loads, loads)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				assert.NotContains(t, err.Error(), "synthetic-sensitive")
			} else {
				require.NoError(t, err)
			}
			entries, err := os.ReadDir(tempDir)
			require.NoError(t, err)
			assert.Empty(t, entries, "plaintext and editor backup must be removed")
			outputBytes, err := os.ReadFile(output)
			if tt.existing || tt.race {
				require.NoError(t, err)
				assert.Equal(t, "keep me", string(outputBytes))
			} else if tt.name == "success" {
				require.NoError(t, err)
				assert.NotContains(t, string(outputBytes), "synthetic-password")
				assert.NotContains(t, string(outputBytes), "stringData:")
				sealed, err := k8s.ReadSealedSecrets(outputBytes)
				require.NoError(t, err)
				require.Len(t, sealed, 1)
				assert.Equal(t, "apps", sealed[0].Namespace)
				for key, expected := range map[string][]byte{"duplicate": []byte("synthetic-password"), "added": []byte("synthetic-value"), "binary": {0, 255}} {
					actual, err := cert.Decrypt(sealed[0].Spec.EncryptedData[key], k8s.GetEncryptionLabel(sealed[0]))
					require.NoError(t, err)
					assert.Equal(t, expected, actual)
				}
			} else {
				require.True(t, os.IsNotExist(err))
			}
		})
	}
}

func TestCreateSecretOutputProtection(t *testing.T) {
	log := logger.New(false)
	defer func() { _ = log.Close() }()
	client := NewClient(log, nil)
	load := func() (*Cert, error) {
		t.Fatal("must not load certificate")
		return nil, fmt.Errorf("unexpected certificate load")
	}
	require.ErrorContains(t, client.CreateSecret("", load), "output file is required")
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "missing.yaml")
	link := filepath.Join(dir, "output.yaml")
	require.NoError(t, os.Symlink(target, link))
	require.ErrorContains(t, client.CreateSecret(link, load), "already exists")
	_, err := os.Stat(target)
	require.True(t, os.IsNotExist(err))
}
