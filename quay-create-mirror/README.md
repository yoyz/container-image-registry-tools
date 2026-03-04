# Quay Mirror Automation Tool

A robust, idempotent, and fully automated Python utility for migrating and mirroring repositories across Red Hat Quay registries. 



Whether you are synchronizing 10 repositories or 10,000, this tool handles discovery, organization creation, robot account provisioning, and TLS-bypassing mirror configurations. Built-in exponential backoff and idempotency mean you can safely run and re-run commands without breaking existing configurations.

## Features

* **Idempotent Operations:** Safely run commands multiple times. The tool intelligently detects existing organizations, robot accounts, and mirror configurations and either skips or gracefully updates them.
* **Resilient API Handling:** Automatically catches `500 Internal Server Error` and API rate limits, applying exponential backoff to retry requests.
* **TLS Bypass:** Easily bypass internal/self-signed certificate errors in lab environments using the `--insecure` flag.
* **Targeted Retries:** Force immediate syncs on specifically failed repositories without interrupting successful ones.
* **Discovery & Auditing:** Automatically discover all accessible repositories and generate clean, color-coded CLI status reports.

## Prerequisites

* Python 3.6+
* `requests` library (`pip install requests`)
* API Tokens for your Source and Target Quay registries (Superuser tokens recommended for full organization/namespace creation).

---

## Command Reference & Examples

### 1. `list` - Discover Source Repositories
Scans the source Quay registry and exports all accessible repositories (or filters by a specific namespace) into a text file.

```bash
python3 quay-create-mirror.py list \
  --src-url [https://source-quay.example.com](https://source-quay.example.com) \
  --src-token YOUR_SOURCE_TOKEN \
  --file repos.txt

```

### 2. `robot` - Prepare Target Namespaces

Reads your repository list and ensures that the corresponding Organizations (namespaces) exist on the target registry. It then provisions a Robot Account in each organization to handle the mirroring.

```bash
python3 quay-create-mirror.py robot \
  --tgt-url [https://target-quay.example.com](https://target-quay.example.com) \
  --tgt-token YOUR_TARGET_TOKEN \
  --robot-name syncbot \
  --file repos.txt

```

### 3. `sync` - Configure Mirroring

The core command. It iterates through your repository list, creates the repositories on the target registry if they don't exist, converts them to `MIRROR` state, and injects the synchronization configuration.

*Note: Use the `--insecure` flag if your target registry does not trust the source registry's SSL certificate.*

```bash
python3 quay-create-mirror.py sync \
  --src-url [https://source-quay.example.com](https://source-quay.example.com) \
  --tgt-url [https://target-quay.example.com](https://target-quay.example.com) \
  --tgt-token YOUR_TARGET_TOKEN \
  --file repos.txt \
  --robot-name syncbot \
  --remote-user "SOURCE_REGISTRY_USER" \
  --remote-pass "SOURCE_REGISTRY_PASS" \
  --insecure

```

### 4. `status` - Check Mirror Health

Queries the target registry and outputs a clean report showing the exact synchronization state (`SUCCESS`, `SYNCING`, `FAILED`, `SCHEDULED`, `NEVER_RUN`) of your repositories.

**Check status from a file:**

```bash
python3 quay-create-mirror.py status \
  --tgt-url [https://target-quay.example.com](https://target-quay.example.com) \
  --tgt-token YOUR_TARGET_TOKEN \
  --file repos.txt

```

**Check status of ALL repositories on the target registry:**

```bash
python3 quay-create-mirror.py status \
  --tgt-url [https://target-quay.example.com](https://target-quay.example.com) \
  --tgt-token YOUR_TARGET_TOKEN \
  --all

```

### 5. `sync-now` - Force Immediate Synchronization

Bypass the standard 24-hour retry interval and force the Quay backend workers to sync immediately.

**Pro-tip:** Use the `--failed-only` flag to quickly retry only the repositories that are currently in an `ERROR` or `FAIL` state.

```bash
python3 quay-create-mirror.py sync-now \
  --tgt-url [https://target-quay.example.com](https://target-quay.example.com) \
  --tgt-token YOUR_TARGET_TOKEN \
  --file repos.txt \
  --failed-only

```

### 6. `get-cert` - Fetch and Verify TLS Certificates

A handy utility to download the full SSL/TLS PEM certificate chain from any registry. It will tell you if your local OS currently trusts the certificate and allows you to save it for manual trust-store injection.

```bash
python3 quay-create-mirror.py get-cert \
  --url [https://source-quay.example.com](https://source-quay.example.com) \
  --out source-quay.crt

```

### 7. `cleanup` - Nuke and Pave

Safely deletes the repositories listed in your text file from the target registry. Requires interactive confirmation to prevent accidents.

```bash
python3 quay-create-mirror.py cleanup \
  --tgt-url [https://target-quay.example.com](https://target-quay.example.com) \
  --tgt-token YOUR_TARGET_TOKEN \
  --file repos.txt

```

---

## Typical Workflow Example

1. **Map the source:** `python3 quay-create-mirror.py list --src-url ... > repos.txt`
2. **Prep the target:** `python3 quay-create-mirror.py robot --tgt-url ... --file repos.txt`
3. **Configure the mirrors:** `python3 quay-create-mirror.py sync --src-url ... --tgt-url ... --insecure`
4. **Monitor progress:** `python3 quay-create-mirror.py status --tgt-url ... --all`
5. **Retry failures:** `python3 quay-create-mirror.py sync-now --tgt-url ... --failed-only`

```

