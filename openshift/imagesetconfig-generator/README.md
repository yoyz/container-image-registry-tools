# OpenShift ImageSetConfiguration Generator

A Python utility to automate the creation of `ImageSetConfiguration` YAML files for OpenShift's `oc-mirror` tool.

Manually crafting configuration files for disconnected (air-gapped) cluster updates is tedious and error-prone. 
This tool connects to an Operator Catalog image (e.g., `redhat-operator-index`), extracts the internal File-Based Catalog (FBC) data, and reverse-engineers a perfect configuration file containing all available packages and channels.

## Features

* **Automated Discovery:** Pulls the catalog image and inspects the internal `/configs` directory of this catalog.
* **Version Support:** Supports both `oc-mirror` **v1** (`mirror.openshift.io/v1alpha2`) and **v2** (`mirror.openshift.io/v2alpha1`).
* **Smart Sorting:** Uses natural sorting for channels (e.g., ensures `4.10` comes after `4.9`).
* **Flexible Fetching:**
* Handles TLS verification toggling.
* **GPG Bypass:** Includes a `--disable-signature-policy` flag to force-pull Red Hat images on systems where gpg signature prevent it.
* Configurable timeouts for slow connections.



## Prerequisites

* **Python 3.x**
* **Podman:** The script wraps Podman CLI commands (`pull`, `create`, `cp`). Podman must be installed and available in your system `$PATH`.
* **Python Libraries:**
```bash
pip install pyyaml

```



## Installation

1. Clone this repository.
2. Make the script executable:
```bash
chmod +x imagesetconfig-generator.py

```



## Usage

The general syntax is:

```bash
./imagesetconfig-generator.py -c <CATALOG_IMAGE> [OPTIONS]

```

### Command Line Arguments

| Argument | Required | Description |
| --- | --- | --- |
| `-c`, `--catalog` | **Yes** | The full URL of the catalog image (e.g., `registry.redhat.io/redhat/redhat-operator-index:v4.16`). |
| `--fetch` | No | Authenticates and pulls the image using Podman. |
| `--extract` | No | Creates a temp container and extracts the FBC configs to disk in /tmp/. |
| `--generate` | No | The output filename for the YAML config (e.g., `myset.yaml`). |
| `--v1` / `--v2` | No | Toggle between `v1alpha2` (v1) and `v2alpha1` (v2) output formats. |
| `--configs` | No | Path to a local directory containing FBC files (if skipping fetch/extract), by default it is on /tmp/. |
| `--disable-signature-policy` | No | Bypasses GPG signature verification, useful if your container gpg policy prevent it. |
| `--tls-verify` | No | Toggle TLS verification (`true`/`false`). Default is `true`. |
| `--timeout` | No | Timeout in seconds for the pull operation (default: 600). |

## Workflow & Examples

The tool is designed to run the following pipeline by default : **Fetch**  **Extract**  **Generate**.
But you can launch each step manually.
The fetch is done by podman pull, and is only done one time on the first fetch and the catalog image stay on the disk.
You have to manually remove that catalog image if you don't plane to use that program a second time.

### 1. The "All-in-One" Run

This authenticates, pulls the image, extracts the config, and generates a **v2** compatible file.

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.16 \
  --fetch \
  --extract \
  --generate config-v2.yaml \
  --v2

```

### 2. Bypass GPG Signatures (e.g., on macOS/Ubuntu)

If you encounter signature errors pulling Red Hat images, use the bypass flag.

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.15 \
  --fetch \
  --disable-signature-policy \
  --extract \
  --generate config.yaml

```

### 3. Generate from Local Configs

If you have already extracted the FBC data to a folder (e.g., `/tmp/my_configs`), you can generate the YAML without connecting to a registry.

```bash
./imagesetconfig-generator.py \
  -c my-catalog:v1 \
  --configs /tmp/my_configs \
  --generate offline-config.yaml \
  --v1

```

## Output Format

The tool generates a valid `ImageSetConfiguration` YAML.

**Example Output (v2):**

```yaml
apiVersion: mirror.openshift.io/v2alpha1
kind: ImageSetConfiguration
mirror:
  operators:
  - catalog: registry.redhat.io/redhat/redhat-operator-index:v4.16
    packages:
    - name: advanced-cluster-management
      channels:
      - name: release-2.9
      - name: release-2.10
      defaultChannel: release-2.10
      _default: release-2.10  # default

```

## Troubleshooting

* **Authentication Failed:** Ensure you have logged in via Podman before running the script:
```bash
podman login registry.redhat.io

```


* **Timeout:** Large catalog images can take a long time to pull. Increase the limit:
```bash
./imagesetconfig-generator.py ... --timeout 1800

```


