package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// ClientInterface is an interface for Kubernetes client operations
type ClientInterface interface {
	GetSecret(name, namespace string) (*corev1.Secret, error)
	GetSecretsWithLabel(namespace, label string) ([]corev1.Secret, error)
	GetSecretsNameOrLabel(namespace, name, label string) ([]corev1.Secret, error)
}

type Client struct {
	ctx       context.Context
	ClientSet kubernetes.Interface
}

func NewClient(ctx context.Context) (*Client, error) {
	// Use standard Kubernetes config loading rules
	// - Uses KUBECONFIG environment variable if set
	// - Falls back to default path ~/.kube/config
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Client{
		ctx:       ctx,
		ClientSet: clientset,
	}, nil
}

func (c *Client) GetSecret(name, namespace string) (*corev1.Secret, error) {
	secret, err := c.ClientSet.CoreV1().Secrets(namespace).Get(c.ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (c *Client) GetSecretsWithLabel(namespace, label string) ([]corev1.Secret, error) {
	secretList, err := c.ClientSet.CoreV1().Secrets(namespace).List(c.ctx, metav1.ListOptions{
		LabelSelector: label,
	})
	if err != nil {
		return nil, err
	}
	return secretList.Items, nil
}

func (c *Client) GetSecretsNameOrLabel(namespace, name, label string) ([]corev1.Secret, error) {
	var secrets []corev1.Secret
	if name == "" && label == "" {
		return nil, fmt.Errorf("either name or label must be provided")
	}

	if name != "" {
		secret, err := c.GetSecret(name, namespace)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, *secret)
		return secrets, nil
	}

	secretsWithLabel, err := c.GetSecretsWithLabel(namespace, label)
	if err != nil {
		return nil, err
	}
	secrets = append(secrets, secretsWithLabel...)

	return secrets, nil
}
