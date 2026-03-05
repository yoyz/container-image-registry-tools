### README.md

```markdown
# Quay Mirror Automation Tool

A robust, idempotent, and fully automated Python utility for migrating and mirroring repositories across Red Hat Quay registries. 



Whether you are synchronizing 10 repositories or 10,000, this tool handles discovery, organization creation, robot account provisioning, and TLS-bypassing mirror configurations. Built-in exponential backoff and idempotency mean you can safely run and re-run commands at high speeds without breaking existing configurations.

## Features

* **YAML Configuration:** Manage all your endpoints, credentials, and tokens in a clean `config.yaml` file to keep your CLI commands short. Unused parameters for specific commands are intelligently ignored.
* **High-Speed & Resilient:** Runs without artificial delays. If it hits API rate limits or `500 Internal Server Errors`, it automatically catches them and applies exponential backoff (up to 10 retries) before failing.
* **Idempotent Operations:** Safely run commands multiple times. The tool intelligently detects existing organizations, robot accounts, and mirror configurations and either skips or gracefully updates them.
* **TLS Bypass:** Easily bypass internal/self-signed certificate errors in lab environments using the `insecure: true` flag.
* **Targeted Retries:** Force immediate syncs on specifically failed repositories without interrupting successful ones.
* **Robot Management:** Create, list, and clean up the mandatory per-organization robot accounts required by Quay's mirror workers.
* **Discovery & Auditing:** Automatically discover all accessible repositories and generate clean, color-coded CLI status reports.

## Prerequisites

* Python 3.6+
* `requests` library (`pip3 install requests`)
* `pyyaml` library (`pip3 install pyyaml`)
* API Tokens for your Source and Target Quay registries (Superuser tokens required for full organization discovery and creation).

---

## Configuration

Create a `config.yaml` file in the same directory as the script. The script will automatically parse these values and feed them into the commands. Any variables not needed by a specific command will be safely ignored.

```yaml
src-url: "[https://source-quay.example.com](https://source-quay.example.com)"
src-token: "YOUR_SOURCE_SUPERUSER_TOKEN"
tgt-url: "[https://target-quay.example.com](https://target-quay.example.com)"
tgt-token: "YOUR_TARGET_SUPERUSER_TOKEN"
src-user: "adminadmin"
src-pass: "adminadmin"
insecure: true
file: "repos.txt"
interval: 86400
robot-name: "syncbot"

```

*Note: You can override any YAML value at runtime by appending the standard CLI flag (e.g., `--tgt-token TEMP_TOKEN`).*

---

## Command Reference & Examples

### 1. `list` - Discover Source Repositories

Scans the source Quay registry and exports all accessible repositories into a text file.

```bash
python3 quay-create-mirror.py list -c config.yaml --all

```

### 2. Robot Management (`create-robot`, `list-robot`, `delete-robot`)

Quay strictly requires a robot account inside each target organization to execute mirror jobs.

**Create Organizations and Robots (Run this before syncing):**

```bash
python3 quay-create-mirror.py create-robot -c config.yaml

```

**Audit/List existing robots in your target namespaces:**

```bash
python3 quay-create-mirror.py list-robot -c config.yaml

```

**Clean up old robots:**

```bash
python3 quay-create-mirror.py delete-robot -c config.yaml --robot-name oldbot

```

### 3. `sync` - Configure Mirroring

Iterates through your repository list, creates the repositories on the target registry if they don't exist, converts them to `MIRROR` state, and injects the synchronization configuration.

```bash
python3 quay-create-mirror.py sync -c config.yaml

```

### 4. `status` - Check Mirror Health

Queries the target registry and outputs a clean report showing the exact synchronization state (`SUCCESS`, `SYNCING`, `FAILED`, `SCHEDULED`, `NEVER_RUN`).

**Check status of your specific list:**

```bash
python3 quay-create-mirror.py status -c config.yaml

```

**Check status of ALL repositories on the target registry:**

```bash
python3 quay-create-mirror.py status -c config.yaml --all

```

### 5. `sync-now` - Force Immediate Synchronization

Bypass the standard retry interval and force the Quay backend workers to sync immediately.

**Pro-tip:** Use the `--failed-only` flag to selectively retry only the repositories currently in an `ERROR` or `FAIL` state.

```bash
python3 quay-create-mirror.py sync-now -c config.yaml --failed-only

```

### 6. `get-cert` - Fetch and Verify TLS Certificates

Downloads the full SSL/TLS PEM certificate chain from the source registry and evaluates if your local OS trusts it.

```bash
python3 quay-create-mirror.py get-cert -c config.yaml --url [https://source-quay.example.com](https://source-quay.example.com) --out source-quay.crt

```

### 7. `cleanup` - Nuke and Pave

Safely deletes the repositories listed in your text file from the target registry. Requires interactive confirmation.

```bash
python3 quay-create-mirror.py cleanup -c config.yaml

```

---

## Typical Workflow

1. **Map the source:** `python3 quay-create-mirror.py list -c config.yaml --all`
2. **Prep the target:** `python3 quay-create-mirror.py create-robot -c config.yaml`
3. **Configure the mirrors:** `python3 quay-create-mirror.py sync -c config.yaml`
4. **Monitor progress:** `python3 quay-create-mirror.py status -c config.yaml --all`
5. **Retry failures:** `python3 quay-create-mirror.py sync-now -c config.yaml --failed-only`

```

