# Quay Space Consumption tool

A Python script to accurately calculate the **physical storage consumption** of Red Hat Quay and Docker V2 registries.
This script was largely developped using AI tool, with a lot of tweak here and there to ensure correctness of the output.

## 🚀 Key Features

* **Physical Storage Calculation:** Calculates the actual disk usage by deduplicating blobs (layers) across repositories and architectures.
* **Hybrid Authentication:** Token and user/password
* **Token Mode (API v1):** Preferred for Quay. Faster and handles large repositories with thousands of tags efficiently.
* **Registry V2 Mode (User/Pass):** Works with any standard Docker Registry V2.
* **Auto-Authentication:** Automatically detects credentials from `~/.docker/config.json` or Kubernetes auth files.
* **Robust Pagination:** iterates through thousands of repositories and tags using both API offsets and RFC 5988 `Link` headers.
* **Multi-Arch Support:** identifies and sums usage for `amd64`, `arm64`, `ppc64le`, etc.
* **Reporting:** Output to console summary or export to **CSV**.

## 📋 Prerequisites

* Python 3.6+
* `requests` library
* try to use only standard library shipped or available natively with python3

```bash
pip install requests

```

## 🛠 Usage

```bash
python3 quayspaceconsumption.py -u <URL> [OPTIONS]

```

### Options

| Flag | Description |
| -------------- | --- |
| `-u <URL>`     | **Required.** The base URL of the registry (e.g., `https://quay.example.com`). |
| `-t <TOKEN>`   | OAuth Token (Recommended for Quay). Uses the efficient API v1. |
| `-U <USER>`    | Username for standard Registry V2 authentication. |
| `-P <PASS>`    | Password for standard Registry V2 authentication. |
| `-f <FILE>`    | Path to a file containing a specific list of repositories to scan (one per line). |
| `-o <FILE>`    | Export the final report to a CSV file. |
| `-d`           | Enable standard debug output. |
| `--curl-debug` | Print equivalent `curl` commands for every request (useful for network troubleshooting). |
| `-h`           | Show help message. |

---

## 🔐 Authentication Modes

### 1. Token Mode 

Uses the Quay API v1. This is a reliable method for Red Hat Quay, it bypasses some V2 pagination limits.

```bash
python3 quayspaceconsumption.py -u https://quay.example.com -t "Mh2y..."

```

### 2. Auto-Discovery (Docker Config)

If no credentials are provided via flags, the tool automatically searches for credentials in standard locations:

* `~/.docker/config.json`
* `/run/user/1000/containers/auth.json`
* `./config.json`

```bash
# Assumes you have already run 'podman login' or 'docker login'
python3 quayspaceconsumption.py -u https://quay.example.com

```

### 3. User/Password (Registry V2 Standard)

Uses the standard Docker Registry V2 API. Useful for non-Quay registries or when an OAuth token is unavailable.

```bash
python3 quayspaceconsumption.py -u https://registry.example.com -U admin -P mypassword

```

---

## 📖 Examples

### Scan Specific Repositories from a File

If you only want to audit a specific set of repositories (instead of discovering all of them), create a file (e.g., `repos.txt`):

```text
openshift/release
openshift/release-images
# You can comment out lines with #

```

Run the tool :

```bash
python3 quayspaceconsumption.py -u https://quay.example.com -f repos.txt

```

### Generate a CSV Report

Save the repository size breakdown to a file for management reporting.

```bash
python3 quayspaceconsumption.py -u https://quay.example.com -o storage_report.csv

```

---

## 📊 Understanding the Output

The tool provides two distinct metrics:

1. **Repository Summary:** The size of the unique blobs *within* that specific repository.
2. **Final Total (Deduplicated):** The most important number. This is the sum of **unique** blobs across the entire registry.

*Example:* If `Image A` (100MB) and `Image B` (100MB) share the same base layer (90MB), the tool will report:

* Repo A: 100 MB
* Repo B: 100 MB
* **Final Total:** 110 MB (90MB base + 10MB app A + 10MB app B).

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

Unlike standard API calls that simply sum up image sizes, this tool try to calculates the **deduplicated** storage footprint.
Accounting for shared layers between images and architectures. 
It specifically try handles "Zombie" images (where the database metadata points to missing storage layers) to ensure accurate reporting.


## 🐛 Troubleshooting

If you suspect network issues or other weird behavior or permissions errors, you can use the `--curl-debug` flag. 
This will try to print the exact `curl` command for every HTTP request the script makes, allowing you to replicate and debug issues manually in your terminal.

```bash
python3 quayspaceconsumption.py -u https://quay.example.com -t <token> --curl-debug

```


