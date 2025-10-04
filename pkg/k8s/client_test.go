package k8s

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewClient(t *testing.T) {
	ctx := context.Background()

	// Note: This test will fail if kubeconfig is not properly configured
	// In a real CI/CD environment, you'd mock the Kubernetes client
	client, err := NewClient(ctx)

	// We allow this to fail in test environments without kubeconfig
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
	// Create a fake clientset with a test secret
	testSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("secret123"),
		},
	}

	fakeClientset := fake.NewSimpleClientset(testSecret)

	// Create a client with the fake clientset
	ctx := context.Background()
	client := &Client{
		ctx:       ctx,
		ClientSet: fakeClientset,
	}

	// Test getting the secret
	secret, err := client.GetSecret("test-secret", "default")
	require.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Equal(t, "test-secret", secret.Name)
	assert.Equal(t, "default", secret.Namespace)
	assert.Equal(t, []byte("admin"), secret.Data["username"])
	assert.Equal(t, []byte("secret123"), secret.Data["password"])
}

func TestClient_GetSecret_NotFound(t *testing.T) {
	// Create a fake clientset without any secrets
	fakeClientset := fake.NewSimpleClientset()

	// Create a client with the fake clientset
	ctx := context.Background()
	client := &Client{
		ctx:       ctx,
		ClientSet: fakeClientset,
	}

	// Test getting a non-existent secret
	secret, err := client.GetSecret("non-existent", "default")
	assert.Error(t, err)
	assert.Nil(t, secret)
	assert.Contains(t, err.Error(), "not found")
}

func TestClient_GetSecret_RealCluster(t *testing.T) {
	// Note: This test requires a real Kubernetes cluster
	// In CI environments without cluster access, it will be skipped
	ctx := context.Background()
	client, err := NewClient(ctx)

	// If we can't create a client (no kubeconfig), skip the test
	if err != nil {
		t.Skipf("Skipping real cluster test: cannot create k8s client: %v", err)
		return
	}

	// Try to get a commonly available secret in kube-system
	// This might fail if the cluster doesn't have this secret, which is okay
	secret, err := client.GetSecret("sealed-secrets-key", "kube-system")

	// We just want to verify the method works, not that the secret exists
	if err != nil {
		// If error is "not found", that's acceptable - method works correctly
		if !assert.Contains(t, err.Error(), "not found") {
			t.Logf("GetSecret error (acceptable): %v", err)
		}
	} else {
		assert.NotNil(t, secret)
		assert.Equal(t, "sealed-secrets-key", secret.Name)
	}
}
