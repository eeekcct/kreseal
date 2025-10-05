# kreseal

A CLI tool to easily edit and reseal Kubernetes SealedSecrets.

## Overview

`kreseal` simplifies the process of editing SealedSecrets by automatically unsealing, editing, and resealing them. It eliminates the need to manually handle encryption and decryption when updating secrets.

## Installation

```sh
go install github.com/eeekcct/kreseal@latest
```

## Prerequisites

- Kubernetes cluster with [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) controller installed
- Access to the sealed-secrets certificate stored in a Kubernetes Secret
- Valid kubeconfig file (default: `~/.kube/config`)

## Usage

### Edit and Reseal (Default Command)

Edit a SealedSecret file:

```sh
kreseal path/to/sealedsecret.yaml
```

This command unseals the SealedSecret, opens it in your editor, and reseals it after editing.

### Seal Command

Convert a plain Kubernetes Secret to a SealedSecret:

```sh
kreseal seal secret.yaml -o sealedsecret.yaml
```

This command reads a Secret file and encrypts it to a SealedSecret.

### Options

**Global Options:**

- `-s, --secrets-name`: Name of the sealed-secrets certificate secret (default: `sealed-secrets`)
- `-n, --namespace`: Namespace of the sealed-secrets certificate (default: `default`)
- `--debug`: Enable debug logging

**Seal Command Options:**

- `-o, --output`: Output file for the SealedSecret (required)

### Examples

```sh
# Edit a SealedSecret with custom certificate location
kreseal -s my-sealed-secrets -n kube-system mysealedsecret.yaml

# Enable debug logging
kreseal --debug mysealedsecret.yaml

# Seal a Secret to a SealedSecret
kreseal seal secret.yaml -o sealedsecret.yaml

# Seal with custom certificate location
kreseal seal secret.yaml -o sealedsecret.yaml -s my-sealed-secrets -n kube-system
```

### Editor Configuration

Set your preferred editor using the `EDITOR` environment variable:

```sh
export EDITOR=vim
kreseal mysealedsecret.yaml
```

Default editor is `vi` if `EDITOR` is not set.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
