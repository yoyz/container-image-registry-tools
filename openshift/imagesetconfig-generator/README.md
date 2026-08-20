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
* **Catalog Digest Pin:** Records the catalog image's `sha256` digest as a comment below the `catalog:` line, so you can reproduce an identical `ImageSetConfiguration` even if the tag is retagged upstream.
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
| `--oc-mirror-list-operators` | No | Prints a `NAME / DISPLAY NAME / DEFAULT CHANNEL` table mirroring `oc-mirror list operators`. Requires extracted configs (combine with `--extract`, or pass `--configs`). |
| `--list-operators` | No | Prints just the operator names, one per line (no header or columns). Requires extracted configs (combine with `--extract`, or pass `--configs`). |
| `--from-operator-list` | No | Path to a file of operator names (one per line) restricting `--generate` to those operators only. Unknown operators cause a non-zero exit listing every missing name; use `--continue-on-error` to generate anyway. |
| `--continue-on-error` | No | Used with `--from-operator-list`: generate the config even when some listed operators are not in the catalog (mirrors `oc-mirror v1 --continue-on-error`). |
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

### 5. List Operators (mirror `oc-mirror list operators`)

Print a `NAME / DISPLAY NAME / DEFAULT CHANNEL` table for every operator in the
catalog, replicating the output of `oc-mirror list operators`:

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --extract \
  --oc-mirror-list-operators

```

Example output:

```
NAME                                            DISPLAY NAME                                                 DEFAULT CHANNEL
3scale-operator                                 Red Hat Integration - 3scale - Managed Application Services  threescale-2.16
amq-streams                                     Streams for Apache Kafka                                     stable
amq-streams-console                             Streams for Apache Kafka Console                             stable
advanced-cluster-management                     Advanced Cluster Management for Kubernetes                   release-2.17
```

The display name is read from each bundle's `olm.csv.metadata` property (when
present in the catalog); operators without one show `-`. Like `oc-mirror`, if
you want both the ImageSetConfiguration YAML *and* the operator table, combine
this flag with `--generate`.

### 6. List Operator Names Only

Print just the operator names, one per line (no header or columns), useful for
feeding into scripts or loops:

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --list-operators

```

Example output:

```
3scale-operator
advanced-cluster-management
amq7-interconnect-operator
amq-broker-rhel8
amq-streams
...
```

### 7. Generate from an Operator List

Restrict `--generate` to a curated set of operators (e.g. from your
`--list-operators` output) instead of dumping every package in the catalog.
Create a file with one operator name per line:

```
amq-streams
3scale-operator
openshift-gitops-operator
```

Then generate a config containing only those operators:

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --from-operator-list operators.txt \
  --generate config.yaml

```

All the usual generation flags still apply (`--v2`, `--version-comment`,
`--min-max-version`, `--configs`). If a name in the list is missing from the
catalog, the tool lists **all** missing operators and exits without writing a
file (so you can fix your list). To generate anyway for the operators that were
found, add `--continue-on-error`:

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --from-operator-list operators.txt \
  --continue-on-error \
  --generate config.yaml

```

## Output Format

The tool generates a valid `ImageSetConfiguration` YAML.

**Example Output (v2, with `--version-comment --min-max-version`):**

```yaml
apiVersion: mirror.openshift.io/v2alpha1
kind: ImageSetConfiguration
mirror:
  operators:
  # catalog: registry.redhat.io/redhat/redhat-operator-index@sha256:7ee16003e0e7e13e0905fca1a981dab22cfe245f5a4e038b420be50dc624a9e5
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

The `# catalog: <...@sha256:...>` comment (below the `catalog:` line) pins the
exact digest of the catalog image used to generate this file. Since tags can be
retagged upstream over time, mirroring by digest

```
podman pull registry.redhat.io/redhat/redhat-operator-index@sha256:7ee16003...
```

is the only way to guarantee you get the *same* set of operators. The digest is
resolved from the locally stored image; if it is not available locally (e.g.
using `--configs` on a machine without the image pulled), the comment is
omitted and a note is printed, but generation still succeeds.

## Troubleshooting

* **Authentication Failed:** Ensure you have logged in via Podman before running the script:
```bash
podman login registry.redhat.io

```


* **Timeout:** Large catalog images can take a long time to pull. Increase the limit:
```bash
./imagesetconfig-generator.py ... --timeout 1800

```


