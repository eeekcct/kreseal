package k8s

import (
	"testing"

	"github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestReadSecrets(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantCount   int
		wantErr     bool
	}{
		{
			name: "single secret",
			yamlContent: `---
kind: Secret
apiVersion: v1
metadata:
  name: my-secret
type: Opaque
data:
  username: dGVzdA==`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "multiple secrets",
			yamlContent: `---
kind: Secret
apiVersion: v1
metadata:
  name: secret1
type: Opaque
data:
  key1: dmFsdWUx
---
kind: Secret
apiVersion: v1
metadata:
  name: secret2
type: Opaque
data:
  key2: dmFsdWUy`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:        "empty content",
			yamlContent: "",
			wantCount:   0,
			wantErr:     false,
		},
		{
			name: "non-secret resource",
			yamlContent: `---
kind: ConfigMap
apiVersion: v1
metadata:
  name: my-config`,
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := ReadSecrets([]byte(tt.yamlContent))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, secrets, tt.wantCount)
			}
		})
	}
}

func TestReadSealedSecrets(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantCount   int
		wantErr     bool
	}{
		{
			name: "valid sealedsecret",
			yamlContent: `---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-secret
  namespace: default
spec:
  encryptedData:
    username: AgA...`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "multiple sealedsecrets",
			yamlContent: `---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: secret1
spec:
  encryptedData:
    key1: AgA1...
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: secret2
spec:
  encryptedData:
    key2: AgA2...`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:        "empty content",
			yamlContent: "",
			wantCount:   0,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sealedSecrets, err := ReadSealedSecrets([]byte(tt.yamlContent))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, sealedSecrets, tt.wantCount)
			}
		})
	}
}

func TestNewSecret(t *testing.T) {
	data := map[string][]byte{
		"username": []byte("test"),
		"password": []byte("secret"),
	}

	spec := v1alpha1.SecretTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Labels: map[string]string{
				"app": "myapp",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	secret := NewSecret(data, spec)

	assert.Equal(t, "v1", secret.APIVersion)
	assert.Equal(t, "Secret", secret.Kind)
	assert.Equal(t, "test-secret", secret.Name)
	assert.Equal(t, "default", secret.Namespace)
	assert.Equal(t, corev1.SecretTypeOpaque, secret.Type)
	assert.Equal(t, data, secret.Data)
	assert.Equal(t, "myapp", secret.Labels["app"])
}

func TestNewSecret_WithImmutable(t *testing.T) {
	immutable := true
	spec := v1alpha1.SecretTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-secret",
		},
		Type:      corev1.SecretTypeOpaque,
		Immutable: &immutable,
	}

	secret := NewSecret(map[string][]byte{"key": []byte("value")}, spec)

	require.NotNil(t, secret.Immutable)
	assert.True(t, *secret.Immutable)
}

func TestNewSealedSecret(t *testing.T) {
	encryptedData := map[string]string{
		"username": "AgAencrypted1...",
		"password": "AgAencrypted2...",
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Labels: map[string]string{
				"app": "myapp",
			},
			Annotations: map[string]string{
				"description": "test",
			},
		},
		Type: corev1.SecretTypeOpaque,
	}

	ss := NewSealedSecret(encryptedData, secret)

	assert.Equal(t, "bitnami.com/v1alpha1", ss.APIVersion)
	assert.Equal(t, "SealedSecret", ss.Kind)
	assert.Equal(t, "test-secret", ss.Name)
	assert.Equal(t, "default", ss.Namespace)
	assert.Equal(t, encryptedData["username"], ss.Spec.EncryptedData["username"])
	assert.Equal(t, encryptedData["password"], ss.Spec.EncryptedData["password"])
	assert.Equal(t, corev1.SecretTypeOpaque, ss.Spec.Template.Type)
	assert.Equal(t, "myapp", ss.Spec.Template.ObjectMeta.Labels["app"])
	assert.Equal(t, "test", ss.Spec.Template.ObjectMeta.Annotations["description"])
}

func TestNewSealedSecret_WithImmutable(t *testing.T) {
	immutable := true
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Type:      corev1.SecretTypeOpaque,
		Immutable: &immutable,
	}

	ss := NewSealedSecret(map[string]string{"key": "encrypted"}, secret)

	require.NotNil(t, ss.Spec.Template.Immutable)
	assert.True(t, *ss.Spec.Template.Immutable)
}

func TestGetEncryptionLabel(t *testing.T) {
	ss := &v1alpha1.SealedSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
		},
	}

	label := GetEncryptionLabel(ss)
	assert.NotNil(t, label)
	assert.NotEmpty(t, label)
}

func TestGetEncryptionLabelFromSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
		},
	}

	label := GetEncryptionLabelFromSecret(secret)
	assert.NotNil(t, label)
	assert.NotEmpty(t, label)
}

func TestReadSecrets_InvalidYAML(t *testing.T) {
	invalidYAML := `
kind: Secret
metadata:
  name: test
  invalid yaml structure: [
`
	secrets, err := ReadSecrets([]byte(invalidYAML))
	assert.Error(t, err)
	assert.Nil(t, secrets)
}

func TestReadSealedSecrets_InvalidYAML(t *testing.T) {
	invalidYAML := `
kind: SealedSecret
metadata:
  name: test
  invalid yaml structure: [
`
	sealedSecrets, err := ReadSealedSecrets([]byte(invalidYAML))
	assert.Error(t, err)
	assert.Nil(t, sealedSecrets)
}

func TestNewSecret_EmptyData(t *testing.T) {
	spec := v1alpha1.SecretTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name: "empty-secret",
		},
		Type: corev1.SecretTypeOpaque,
	}

	secret := NewSecret(map[string][]byte{}, spec)
	assert.NotNil(t, secret)
	assert.Empty(t, secret.Data)
}

func TestNewSealedSecret_EmptyLabelsAndAnnotations(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
	}

	ss := NewSealedSecret(map[string]string{"key": "value"}, secret)
	assert.NotNil(t, ss)
	assert.Equal(t, "test-secret", ss.Name)
	assert.Empty(t, ss.Labels)
	assert.Empty(t, ss.Annotations)
}
