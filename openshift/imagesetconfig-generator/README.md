# OpenShift ImageSetConfiguration Generator

A Python utility to automate the creation of `ImageSetConfiguration` YAML files for OpenShift's `oc-mirror` tool.

Manually crafting configuration files for disconnected (air-gapped) cluster updates is tedious and error-prone. 
This tool connects to an Operator Catalog image (e.g., `redhat-operator-index`, `community-operators`, `certified-operators`), extracts the internal File-Based Catalog (FBC) data, and generates a perfect `ImageSetConfiguration` file containing all available packages and channels.

For a deep dive into how catalog images are built and how this tool deciphers them, see [doc/design.md](doc/design.md).

## Features

* **Automated Discovery:** Pulls the catalog image and inspects the internal `/configs` directory of this catalog.
* **Version Support:** Supports both `oc-mirror` **v1** (`mirror.openshift.io/v1alpha2`) and **v2** (`mirror.openshift.io/v2alpha1`).
* **Smart Sorting:** Uses natural sorting for channels (e.g., ensures `4.10` comes after `4.9`).
* **Version Listing (`--version-comment`):** Adds the full list of available versions as a comment below each channel, making it easy to pick versions.
* **minVersion/maxVersion (`--min-max-version`):** Automatically emits `minVersion`/`maxVersion` keys per channel from the channel's version list. Can be combined with `--version-comment`.
* **Flexible Fetching:**
  * Handles TLS verification toggling.
  * Configurable timeouts for slow connections.
* **GPG Bypass:** Includes a `--disable-signature-policy` flag for non-Red Hat systems where podman has signature verification enabled but the Red Hat GPG key is not in the trust store.



## Prerequisites

* **Python 3.x**
* **Podman:** The script wraps Podman CLI commands (`pull`, `create`, `cp`). Podman must be installed and available in your system `$PATH`.
* **Python Libraries:** `pyyaml`. Install it with pip, or from your distribution's package manager:
```bash
pip install pyyaml
```
```bash
sudo dnf install python3-pyyaml   # Fedora/RHEL
sudo apt install python3-yaml     # Debian/Ubuntu

```



## Installation

Only `imagesetconfig-generator.py` is needed to run the tool — copy it anywhere, make it executable, and you're set:

```bash
chmod +x imagesetconfig-generator.py

```

The `tests/` directory is only required if you want to run the test suite.

## Testing

The test suite covers FBC parsing and YAML generation against the real codebase, using only the Python standard library (`unittest`) and `pyyaml`.

See [tests/README.md](tests/README.md) for the full test infrastructure documentation.

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```



## Usage

The general syntax is:

```bash
./imagesetconfig-generator.py -c <CATALOG_IMAGE> [OPTIONS]

```

### Command Line Arguments

| Argument | Required | Description |
| --- | --- | --- |
| `-c`, `--catalog` | **Yes** | The full URL of the catalog image (e.g., `registry.redhat.io/redhat/redhat-operator-index:v4.20`). |
| `--fetch` | No | Authenticates and pulls the image using Podman. |
| `--extract` | No | Creates a temp container and extracts the FBC configs to disk in /tmp/. |
| `--generate` | No | The output filename for the YAML config (e.g., `myset.yaml`). |
| `--v1` / `--v2` | No | Toggle between `v1alpha2` (v1) and `v2alpha1` (v2) output formats. |
| `--configs` | No | Path to a local directory containing FBC files (if skipping fetch/extract), by default it is on /tmp/. |
| `--disable-signature-policy` | No | Bypasses GPG signature verification when podman has it enabled but the Red Hat GPG key is missing from the trust store. Use only with registries you trust. |
| `--tls-verify` | No | Toggle TLS verification (`true`/`false`). Default is `true`. |
| `--timeout` | No | Timeout in seconds for the pull operation (default: 600). |
| `--version-comment` | No | Adds the full list of available versions as a comment below each channel. |
| `--min-max-version` | No | Adds `minVersion`/`maxVersion` keys per channel based on the available versions. Can be combined with `--version-comment`. |
| `--verbose` | No | Enables verbose logging of file processing during generation. |

## Workflow & Examples

The tool is designed to run the following pipeline by default : **Fetch**  **Extract**  **Generate**.
But you can launch each step manually.
The fetch is done by podman pull, and is only done one time on the first fetch and the catalog image stay on the disk.
You have to manually remove that catalog image if you don't plan to use that program a second time.

By default the extracted FBC configs are written to `/tmp/<sanitized-catalog>/` (e.g. `/tmp/registry_redhat_io_redhat_redhat-operator-index_v4_20/`), so the extract step consumes disk space in your `/tmp` folder. Use `--configs` to point the tool at another location.

### 1. The "All-in-One" Run

This authenticates, pulls the image, extracts the config, and generates a **v2** compatible file.

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --fetch \
  --extract \
  --generate config-v2.yaml \
  --v2

```

### 2. Bypass GPG Signature Policy (non-Red Hat systems)

On systems where podman has signature verification enabled but Red Hat's GPG
keys are not present in the trust store (e.g. standard Fedora/Ubuntu podman
installs, where the pull of a Red Hat image fails with a signature error), the
`--disable-signature-policy` flag bypasses that check. Only use it when you
trust the registry you are pulling from:

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --fetch \
  --disable-signature-policy \
  --extract \
  --generate config.yaml

```

### 3. Generate from Local Configs

If you have already extracted the FBC data to a folder (e.g., `/tmp/my_configs`), you can generate the YAML without pulling the image a second time from the registry.

```bash
./imagesetconfig-generator.py \
  -c my-catalog:v1 \
  --configs /tmp/my_configs \
  --generate offline-config.yaml \
  --v1

```

### 4. Add Available Versions / minVersion & maxVersion

Add the full list of available versions as a comment below each channel, plus
auto-generated `minVersion`/`maxVersion` keys for use with `oc-mirror`:

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --generate config.yaml \
  --v2 \
  --version-comment \
  --min-max-version

```

## Output Format

The tool generates a valid `ImageSetConfiguration` YAML.

**Example Output (v2, with `--version-comment --min-max-version`):**

```yaml
apiVersion: mirror.openshift.io/v2alpha1
kind: ImageSetConfiguration
mirror:
  operators:
  - catalog: registry.redhat.io/redhat/redhat-operator-index:v4.20
    packages:
    - name: quay-operator
      channels:
      - name: stable-3.6
      # versions: 3.6.0, 3.6.1, 3.6.2, 3.6.4, 3.6.5, 3.6.6, 3.6.7, 3.6.8, 3.6.9, 3.6.10
        minVersion: 3.6.0
        maxVersion: 3.6.10
      - name: stable-3.17  # default
      # versions: 3.17.0, 3.17.1, 3.17.2, 3.17.3
        minVersion: 3.17.0
        maxVersion: 3.17.3
      defaultChannel: stable-3.17

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


