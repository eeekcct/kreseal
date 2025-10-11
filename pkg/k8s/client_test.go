package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// newFakeClient creates a new Client with a fake ClientSet for testing
func newFakeClient(objects ...runtime.Object) *Client {
	fakeClientset := fake.NewSimpleClientset(objects...)
	return &Client{
		ctx:       context.Background(),
		ClientSet: fakeClientset,
	}
}

// newTestSecret creates a test Secret with the given name, namespace, and data
func newTestSecret(name, namespace string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
}

// newTestSecretWithLabels creates a test Secret with labels
func newTestSecretWithLabels(name, namespace string, data map[string][]byte, labels map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Data: data,
	}
}

// newFakeClientWithError creates a fake client that returns errors for specific operations
func newFakeClientWithError(errorOnList bool) *Client {
	fakeClientset := fake.NewSimpleClientset()

	if errorOnList {
		fakeClientset.PrependReactor("list", "secrets", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, errors.New("simulated list error")
		})
	}

	return &Client{
		ctx:       context.Background(),
		ClientSet: fakeClientset,
	}
}

func TestNewClient(t *testing.T) {
	ctx := context.Background()

	client, err := NewClient(ctx)

	if err != nil {
		assert.Error(t, err)
		assert.Nil(t, client)
	} else {
		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.NotNil(t, client.ClientSet)
		assert.NotNil(t, client.ctx)
		assert.Equal(t, ctx, client.ctx)
	}
}

func TestClient_GetSecret_Success(t *testing.T) {
	testSecret := newTestSecret("test-secret", "default", map[string][]byte{
		"username": []byte("admin"),
		"password": []byte("secret123"),
	})

	client := newFakeClient(testSecret)

	secret, err := client.GetSecret("test-secret", "default")
	require.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Equal(t, "test-secret", secret.Name)
	assert.Equal(t, "default", secret.Namespace)
	assert.Equal(t, []byte("admin"), secret.Data["username"])
	assert.Equal(t, []byte("secret123"), secret.Data["password"])
}

func TestClient_GetSecret_NotFound(t *testing.T) {
	client := newFakeClient()

	// Test getting a non-existent secret
	secret, err := client.GetSecret("non-existent", "default")
	assert.Error(t, err)
	assert.Nil(t, secret)
	assert.Contains(t, err.Error(), "not found")
}

func TestClient_GetSecretsWithLabel(t *testing.T) {
	// Create test secrets with different labels
	secret1 := newTestSecretWithLabels("secret1", "default",
		map[string][]byte{"key1": []byte("value1")},
		map[string]string{"app": "myapp", "env": "prod"})

	secret2 := newTestSecretWithLabels("secret2", "default",
		map[string][]byte{"key2": []byte("value2")},
		map[string]string{"app": "myapp", "env": "dev"})

	secret3 := newTestSecretWithLabels("secret3", "default",
		map[string][]byte{"key3": []byte("value3")},
		map[string]string{"app": "other", "env": "prod"})

	client := newFakeClient(secret1, secret2, secret3)

	// Test getting secrets with app=myapp label
	secrets, err := client.GetSecretsWithLabel("default", "app=myapp")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)

	secretNames := make([]string, len(secrets))
	for i, s := range secrets {
		secretNames[i] = s.Name
	}
	assert.Contains(t, secretNames, "secret1")
	assert.Contains(t, secretNames, "secret2")
}

func TestClient_GetSecretsWithLabel_NotFound(t *testing.T) {
	client := newFakeClient()
	secrets, err := client.GetSecretsWithLabel("default", "app=nonexistent")
	require.NoError(t, err)
	assert.Len(t, secrets, 0)
}

func TestClient_GetSecretsWithLabel_InvalidSelector(t *testing.T) {
	client := newFakeClient()

	defer func() {
		if r := recover(); r != nil {
			assert.Contains(t, r.(error).Error(), "invalid selector")
		}
	}()

	client.GetSecretsWithLabel("default", "invalid=selector=syntax")
	t.Error("Expected panic but none occurred")
}

func TestClient_GetSecretsWithLabel_APIError(t *testing.T) {
	client := newFakeClientWithError(true)

	secrets, err := client.GetSecretsWithLabel("default", "app=myapp")
	assert.Error(t, err)
	assert.Nil(t, secrets)
	assert.Contains(t, err.Error(), "simulated list error")
}

func TestClient_GetSecretsNameOrLabel(t *testing.T) {
	secret1 := newTestSecretWithLabels("secret1", "default",
		map[string][]byte{"key1": []byte("value1")},
		map[string]string{"app": "myapp", "env": "prod"})
	secret2 := newTestSecretWithLabels("secret2", "default",
		map[string][]byte{"key2": []byte("value2")},
		map[string]string{"app": "myapp", "env": "dev"})
	secret3 := newTestSecretWithLabels("secret3", "default",
		map[string][]byte{"key3": []byte("value3")},
		map[string]string{"app": "other", "env": "prod"})

	client := newFakeClient(secret1, secret2, secret3)

	tests := []struct {
		name       string
		secretName string
		label      string
		wantCount  int
		wantErr    bool
	}{
		{
			name:       "by name",
			secretName: "secret1",
			label:      "",
			wantCount:  1,
			wantErr:    false,
		},
		{
			name:       "by label",
			secretName: "",
			label:      "app=myapp",
			wantCount:  2,
			wantErr:    false,
		},
		{
			name:       "not found by name",
			secretName: "non-existent",
			label:      "",
			wantCount:  0,
			wantErr:    true,
		},
		{
			name:       "not found by label",
			secretName: "",
			label:      "app=nonexistent",
			wantCount:  0,
			wantErr:    false,
		},
		{
			name:       "empty name and label",
			secretName: "",
			label:      "",
			wantCount:  0,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := client.GetSecretsNameOrLabel("default", tt.secretName, tt.label)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, secrets)
			} else {
				require.NoError(t, err)
				assert.Len(t, secrets, tt.wantCount)
			}
		})
	}
}
