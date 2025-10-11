package k8s

import (
	"bytes"
	"errors"
	"io"
	"sort"

	"github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const (
	sealedSecretKeyLabel = "sealedsecrets.bitnami.com/sealed-secrets-key"
)

func SealedSecretKeySelector() string {
	return fields.OneTermEqualSelector(sealedSecretKeyLabel, "active").String()
}

func NewSecret(data map[string][]byte, spec v1alpha1.SecretTemplateSpec) *corev1.Secret {
	secret := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: spec.ObjectMeta,
		Type:       spec.Type,
		Data:       data,
	}
	// Preserve Immutable field if set in template
	if spec.Immutable != nil {
		secret.Immutable = spec.Immutable
	}
	return secret
}

func NewSealedSecret(data map[string]string, secret *corev1.Secret) *v1alpha1.SealedSecret {
	// Create metadata with only name and namespace
	sealedSecretMeta := metav1.ObjectMeta{
		Name:      secret.Name,
		Namespace: secret.Namespace,
	}

	template := v1alpha1.SecretTemplateSpec{
		Type:       secret.Type,
		ObjectMeta: secret.ObjectMeta,
	}

	// Preserve Immutable field if set
	if secret.Immutable != nil {
		template.Immutable = secret.Immutable
	}

	return &v1alpha1.SealedSecret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "bitnami.com/v1alpha1", Kind: "SealedSecret"},
		ObjectMeta: sealedSecretMeta,
		Spec: v1alpha1.SealedSecretSpec{
			EncryptedData: data,
			Template:      template,
		},
	}
}

func GetEncryptionLabel(ss *v1alpha1.SealedSecret) []byte {
	return v1alpha1.EncryptionLabel(ss.Namespace, ss.Name, ss.Scope())
}

func GetEncryptionLabelFromSecret(secret *corev1.Secret) []byte {
	scope := v1alpha1.SecretScope(secret.GetObjectMeta())
	return v1alpha1.EncryptionLabel(secret.Namespace, secret.Name, scope)
}

func ReadSecrets(raw []byte) ([]*corev1.Secret, error) {
	var secrets []*corev1.Secret

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	for {
		var secret corev1.Secret
		err := decoder.Decode(&secret)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}

		if secret.Kind != "Secret" {
			continue
		}

		secrets = append(secrets, &secret)
	}
	return secrets, nil
}

func ReadSealedSecrets(raw []byte) ([]*v1alpha1.SealedSecret, error) {
	var sealedSecrets []*v1alpha1.SealedSecret

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	for {
		var sealedSecret v1alpha1.SealedSecret
		err := decoder.Decode(&sealedSecret)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}

		if sealedSecret.Kind != "SealedSecret" {
			continue
		}

		sealedSecrets = append(sealedSecrets, &sealedSecret)
	}
	return sealedSecrets, nil
}

func SortSecretsByCreationTimestamp(secrets []corev1.Secret) {
	sort.Sort(v1alpha1.ByCreationTimestamp(secrets))
}
