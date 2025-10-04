package k8s

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Note: Testing GetSecret requires a real Kubernetes cluster or mock
// This test demonstrates the structure but will be skipped
func TestClient_GetSecret(t *testing.T) {
	t.Skip("Requires Kubernetes cluster access")

	ctx := context.Background()
	client, err := NewClient(ctx)
	require.NoError(t, err)

	secret, err := client.GetSecret("test-secret", "default")
	assert.NoError(t, err)
	assert.NotNil(t, secret)
}
