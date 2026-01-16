# Registry List Tool

`quayregistryclient.py` is a Python-based CLI utility for inspecting, managing, and deleting container image registries. 
It supports both the standard **Docker Registry HTTP API V2** and specific **Red Hat Quay API** endpoints.

It is designed for administrators who need to debug registry issues, inspect manifests/blobs, or perform bulk deletion of repositories.

## Features

* **Registry Navigation:** List all repositories (supports pagination) and tags.
* **Deep Inspection:** Retrieve image digests (SHA), raw JSON manifests, and individual blob layers.
* **Authentication:**
* Supports Basic Auth (Username/Password).
* Supports Bearer Tokens.
* **Auto-discovery:** Can read credentials directly from `~/.docker/config.json`.


* **Quay.io Integration:** Includes specific commands for Quay API discovery and repository management.
* **Debug Mode:** Outputs equivalent `curl` commands for every Python request to help you debug API calls manually.

## Prerequisites

* Python 3.x
* `requests` library

```bash
pip install requests

```

## Usage

The script uses a `COMMAND [OPTIONS]` structure.

```bash
./quayregistryclient.py <COMMAND> [OPTIONS]

```

### Common Options

| Option | Description |
| --- | --- |
| `-r`, `--registry_url` | The URL of the registry (e.g., `quay.io` or `myregistry.local`). |
| `-P`, `--Port` | The registry port (defaults to `443` if not specified). |
| `-u`, `--username` | Registry username. |
| `-p`, `--password` | Registry password. |
| `-d` | Enable **Debug Mode** (prints equivalent `curl` commands to stderr). |
| `-h`, `--help` | Show the help message. |

> **Note:** If `-u` and `-p` are omitted, the tool attempts to load credentials from `~/.docker/config.json`.

---

### Commands

#### 1. Discovery & Listing

**List all repositories (Catalog):**

```bash
./quayregistryclient.py list-catalog -r myregistry.com

```

**List tags for a specific image:**

```bash
./quayregistryclient.py list-tags -r myregistry.com -i my-org/my-image

```

**List everything (Images, Tags, and Digests):**

```bash
./quayregistryclient.py list-all -r myregistry.com

```

#### 2. Inspection

**Get an image digest (SHA):**
Requires both image name (`-i`) and tag (`-t`).

```bash
./quayregistryclient.py get-image-digest -r myregistry.com -i my-org/my-image -t latest

```

**Get an image manifest (JSON):**
Requires image name (`-i`) and digest (`-D`).

```bash
./quayregistryclient.py get-image-manifest -r myregistry.com -i my-org/my-image -D sha256:1234...

```

**Get the server SSL certificate:**
Useful for debugging trusted certificate issues.

```bash
./quayregistryclient.py get-server-certificate -r myregistry.com -P 443

```

#### 3. Deletion (Administrative)

**Delete a specific repository:**

```bash
./quayregistryclient.py delete-repo -r myregistry.com -i my-org/my-image -T <token>

```

**Delete ALL repositories (Destructive):**
⚠️ **Warning:** This will wipe the entire registry. You must provide the safety flag.

```bash
./quayregistryclient.py delete-all-repo \
  -r myregistry.com \
  -u admin -p password \
  --i-am-deleting-all-repo

```

### Troubleshooting

If you are having connection or API issues, use the `-d` flag. This will print the exact `curl` command the script is trying to execute.

```bash
./quayregistryclient.py list-catalog -r myregistry.com -d
# Output:
# # curl -X GET 'https://myregistry.com:443/v2/_catalog' -H ...

```

### Reference: Command List

* `get-server-certificate`
* `browse-api`
* `quay-api-discovery`
* `list-catalog`
* `list-tags`
* `list-all`
* `get-image-digest`
* `get-image-manifest`
* `get-blob`
* `delete-repo`
* `delete-all-repo`
* `set-api-path-key-value`

---
