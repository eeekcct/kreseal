package k8s

import (
	"context"
	"flag"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	ctx       context.Context
	ClientSet *kubernetes.Clientset
}

func NewClient(ctx context.Context) (*Client, error) {
	configPath := clientcmd.RecommendedHomeFile
	kubeconfig := flag.String("kubeconfig", configPath, "(optional) absolute path to the kubeconfig file")
	flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
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
