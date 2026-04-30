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
* **Interactive Mode:** ncurses-based tree browser for visual exploration
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

## Reference: Command List

* `get-server-certificate`
* `browse-api`
* `quay-api-discovery`
* `quay-api-listuser`
* `quay-api-delete-user`
* `quay-api-create-user`
* `quay-api-change-userpassword`
* `list-catalog`
* `list-tags`
* `list-all`
* `get-image-digest`
* `get-image-manifest`
* `get-blob`
* `delete-repo`
* `delete-tag`
* `delete-all-repo`
* `set-api-key-value`
* `interactive` - Launch interactive ncurses interface

---

## Interactive Mode

The tool includes an interactive ncurses-based browser for exploring registries visually.

### Launch

```bash
./quayregistryclient.py interactive -r <registry_url> [-P port] [-u username] [-p password]
```

### Features

- **Tree Browser**: Navigate repositories in a hierarchical tree view
- **Node Types**: Registry → Directory → Image → Tag → Manifest → Blob
- **Search**: Press `/` to search, `n/N` to navigate between matches

### Keyboard Controls

| Key | Action |
|-----|--------|
| `Space` | Expand/Collapse directory or image |
| `Up/Down` | Navigate through list |
| `Enter` | View details for image/tag/blob |
| `b` | Go back from details view |
| `q` | Quit |
| `/` | Search for image name |
| `n` | Next search match |
| `N` | Previous search match |

---

## Bash Completion

The tool supports intelligent bash completion with dynamic repository and tag suggestions.

### Installation

Generate and install the completion script:

```bash
# Generate completion script
./quayregistryclient.py --generate-completion > ~/.bash_completion_quay

# Source it in your current shell
source ~/.bash_completion_quay

# Add to ~/.bashrc for persistent completion
echo "source ~/.bash_completion_quay" >> ~/.bashrc
```

### Usage

Once installed, bash completion provides:

- **Command names**: Tab after the script name to see available commands
  ```bash
  ./quayregistryclient.py [TAB]
  # Shows: list-catalog, list-tags, get-image-digest, ...
  ```

- **Options**: Tab after an option to see available flags
  ```bash
  ./quayregistryclient.py list-tags -[TAB]
  # Shows: -r -P -u -p -i -d -h
  ```

- **Repository names**: Tab after `-i` to fetch and suggest repositories from the registry
  ```bash
  ./quayregistryclient.py list-tags -r myregistry.com -P 443 -i [TAB]
  # Fetches repositories from myregistry.com and shows available images
  ```

- **Tag names**: Tab after `-t` to fetch and suggest tags for the specified image
  ```bash
  ./quayregistryclient.py list-tags -r myregistry.com -P 443 -i my-org/my-app -t [TAB]
  # Fetches tags for my-org/my-app and shows available tags
  ```

### Requirements

- Credentials must be configured in `~/.docker/config.json` for dynamic completion
- Alternatively, provide `-T token` with a valid bearer token
- If credentials are missing, completion will show an error message

### Error Handling

- **Registry unreachable**: Shows "Error: Failed to fetch repositories/tags from <registry>"
- **No credentials**: Shows "Error: No token available. Provide -T token or configure ~/.docker/config.json"

---
