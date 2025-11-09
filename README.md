# kreseal

A CLI tool to easily edit and reseal Kubernetes SealedSecrets.

## Overview

`kreseal` simplifies the process of editing SealedSecrets by automatically unsealing, editing, and resealing them. It eliminates the need to manually handle encryption and decryption when updating secrets.

## Installation

### Using Go

```sh
go install github.com/eeekcct/kreseal@latest
```

### Binary Releases

Download pre-built binaries from the [releases page](https://github.com/eeekcct/kreseal/releases).

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

- `-s, --secrets-name`: Name of the sealed-secrets certificate secret
- `-n, --namespace`: Namespace of the sealed-secrets certificate (default: `kube-system`)
- `--debug`: Enable debug logging

**Seal Command Options:**

- `-o, --output`: Output file for the SealedSecret (required)

### Examples

```sh
# Edit a SealedSecret with kreseal
kreseal mysealedsecret.yaml

# Enable debug logging
kreseal --debug mysealedsecret.yaml

# Seal a Secret to a SealedSecret
kreseal seal secret.yaml -o sealedsecret.yaml
```

### Configuration

You can configure default values using:

- Configuration file: `$HOME/.config/kreseal/config.yaml` or specify with `--config`
- Environment variables: Use `KRESEAL_` prefix (e.g., `KRESEAL_SECRETS_NAME`, `KRESEAL_NAMESPACE`)

### Editor Configuration

Set your preferred editor using the `EDITOR` environment variable:

```sh
export EDITOR=vim
kreseal mysealedsecret.yaml
```

Default editor is `vi` if `EDITOR` is not set.

## License

[MIT](./LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
