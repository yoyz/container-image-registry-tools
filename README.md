# Container Image Registry Tools

A collection of Python-based utilities for managing container registries (Docker Distribution/Quay), inspecting images, and generating configurations for OpenShift mirroring.

## 📂 Tools Included

1.  **Registry List Tool** `quayregistryclient`
    * *Purpose:* A CLI for deep inspection and administration of registry content (Tags, Manifests, Blobs) with specific support for Red Hat Quay.
2.  **ImageSetConfiguration Generator** `imagesetconfig-generator.py`
    * *Purpose:* Automates the creation of `ImageSetConfiguration` YAML files for `oc-mirror` by reverse-engineering an existing Operator Catalog.
3.  **Quay Space Consumption tool** 
    * *Purpose:* accurately calculate the **physical storage consumption** of Red Hat Quay and Docker V2 registries.
---

## 🛠️ QuayRegistryClient (`quayregistryclient.py`)

A Swiss Army knife for registry admin. 
It allows you to list repositories, inspect image internals (digests, manifests), and perform removal operations.

### Features
* **Support:** Works with standard Docker Registry V2 API and includes specialized endpoints for **Red Hat Quay** (e.g., `quay-api-discovery`).
* **Deep Inspection:**
    * Retrieve **SHA Digests** for specific tags.
    * Dump raw **JSON Manifests**.
    * Download individual **Blobs** (layers).
    * Fetch the server's **SSL Certificate** for debugging trust issues.
* **Authentication:**
    * Supports Basic Auth and Bearer Tokens.
    * **Auto-Discovery:** Automatically reads credentials from your local `~/.docker/config.json`.
* **Cleanup:** Includes commands to delete specific repositories or **wipe an entire registry** (with safety flags).
* **Debug Mode:** The `-d` flag outputs equivalent `curl` commands for every request, making it easy to debug API interactions.

### Usage
```bash
# List all repositories in the catalog
./quayregistryclient.py list-catalog -r myregistry.example.com -u admin -p password

# Get an image digest
./quayregistryclient.py get-image-digest -r myregistry.example.com -i my-org/my-image -t latest

# Delete a repository (Quay)
./quayregistryclient.py delete-repo -r myregistry.example.com -i my-org/old-image -t <mytag> -T <token>

```

---

## ⚙️ ImageSetConfig Generator (`imagesetconfig-generator.py`)

Generating `ImageSetConfiguration` files for disconnected OpenShift clusters (using `oc-mirror`) is often a manual, error-prone process. This tool automates it by pulling a Catalog Image and extracting its internal File-Based Catalog (FBC) data.

### Features

* **Automated Discovery:** Pulls the catalog image (via `podman`) and extracts the `/configs` directory to find all packages and channels.
* **Version Support:** Generates valid YAML for both **oc-mirror v1** (`mirror.openshift.io/v1alpha2`) and **v2** (`mirror.openshift.io/v2alpha1`).
* **Smart Sorting:** Uses natural sorting (e.g., `4.10` > `4.9`) to ensure channel lists are human-readable.
* **GPG Bypass:** Includes a `--disable-signature-policy` flag to allow pulling Red Hat images on non-RHEL systems (macOS/Ubuntu) where signature verification often fails.
* **Resilience:** Configurable timeouts and TLS verification toggles.

### Usage

```bash
# Generate a v2 config for the Red Hat Operator Index
./imagesetconfig-generator.py \
  --catalog registry.redhat.io/redhat/redhat-operator-index:v4.16 \
  --fetch \
  --extract \
  --generate rh-catalog-v2.yaml \
  --v2

# Generate from a local FBC directory (offline mode)
./imagesetconfig-generator.py \
  --catalog my-local-catalog:v1 \
  --configs /tmp/extracted_configs \
  --generate offline-config.yaml \
  --v1

```

##  🛠 Quay Space Consumption (`quayspaceconsumption.py`)

A Python script to accurately calculate the **physical storage consumption** of Red Hat Quay and Docker V2 registries.
This script was largely developped using AI tool, with a lot of tweak here and there to ensure correctness of the output.


Run the tool :

```bash
python3 quayspaceconsumption.py -u https://quay.example.com -f repos.txt

```

```text
ARCHITECTURE BREAKDOWN (Deduplicated within Arch)
----------------------------------------------------------------
linux/amd64          | 1030,23 MiB
linux/arm64          | 1006,81 MiB
linux/ppc64le        | 1097,61 MiB
linux/s390x          | 1002,85 MiB

REPOSITORY SUMMARY
----------------------------------------------------------------
ubi9/httpd-24                                      | 3794,94 MiB
ubi8/ubi                                           | 299,41 MiB
ubi8/ubi-micro                                     | 43,15 MiB
----------------------------------------------------------------
FINAL TOTAL (Deduplicated physical storage): 4137,50 MiB

```




## 📝 Configuration

### Credentials

The tools are designed to work seamlessly with your existing Docker/Podman login sessions.

