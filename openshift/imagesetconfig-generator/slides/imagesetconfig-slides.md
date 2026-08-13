---
marp: true
theme: default
paginate: true
backgroundColor: #fff
style: |
  section { font-size: 22px; }
---

# OpenShift ImageSetConfiguration Generator

A tool to generate `ImageSetConfiguration` from a redhat catalog image.
Design to reduce the stress of long `oc-mirror` command.

---

## The Problem

Manually crafting `ImageSetConfiguration` YAML files for OpenShift's `oc-mirror` tool is:

- **Tedious** — listing every package and channel by hand
- **Error-prone** — missing a channel means missing operators in your air-gapped cluster
- **Fragile** — catalog images update constantly, manual configs go stale

---

## The Solution

A Python tool that:

1. **Pulls** a catalog image from a container registry
2. **Extracts** the internal File-Based Catalog (FBC) data
3. **Generates** a complete, correct `ImageSetConfiguration` YAML

No manual listing. No guesswork.

---

## What It Produces

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
      # versions: 3.6.0, 3.6.1, 3.6.5, 3.6.6, 3.6.9, 3.6.10
        minVersion: 3.6.0
        maxVersion: 3.6.10
      - name: stable-3.17
      # versions: 3.17.0, 3.17.1, 3.17.2, 3.17.3, 3.17.4
        minVersion: 3.17.0
        maxVersion: 3.17.4
      defaultChannel: stable-3.17
```

---

## Usage

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --fetch --extract --generate config.yaml --v2
```

Three steps in one command: **Fetch → Extract → Generate**

---

## Prerequisites

| Requirement   | Purpose                      |
|---------------|------------------------------|
| Python 3.x    | Script runtime                  |
| `pyyaml`      | YAML generation                   |
| Podman CLI    | Pull and extract catalog images |

```bash
sudo dnf install python3-pyyaml   # Fedora/RHEL
sudo apt install python3-yaml     # Debian/Ubuntu
pip install pyyaml                # Others
```

---

## Pipeline Overview

```
┌──────────┐       ┌──────────┐       ┌──────────┐
│  FETCH   │──────>│ EXTRACT  │──────>│ GENERATE │
│ Podman   │       │ Container│       │ FBC Walk │
│  pull    │       │  cp      │       │ YAML out │
└──────────┘       └──────────┘       └──────────┘
     │                  │                  │
  catalog image      /configs          config.yaml
  in registry         on disk
```

Each step can run standalone or chained.
A catalog won't be pulled a second time ( cached ) if it has not been updated.

---

## What Is a Catalog Image?

A container image that contains an **Operator Lifecycle Manager (OLM)** catalog.
The catalog image run as a pod in **openshift-marketplace** namespace.
It bundles all operator metadata, packages, channels, and bundle manifests for an OpenShift distribution.

Common examples:

| Catalog                    | Description                 |
|----------------------------|-----------------------------|
| `redhat-operator-index`    | Red Hat certified operators |
| `community-operators-prod` | Community operators         |
| `certified-operators`      | Vendor-certified operators  |

---

## Inside a Catalog Image

A catalog image follows the **File-Based Catalog (FBC)** format.

Its filesystem is organized as:

```
/configs/
├── cockroachdb-certified/              # single concatenated JSON file
│   └── catalog.json                    #   package + channels + bundles in one stream
├── aikit-operator/
│   └── catalog.json                    # single concatenated JSON file
├── patterns-operator/
│   ├── package.json                    # olm.package blob
│   ├── channels.json                   # olm.channel blobs
│   └── bundles.json                    # olm.bundle blobs
├── victoriametrics-operator/
│   └── catalog.yaml                    # single YAML file (package + channels + bundles)
├── opendatahub-operator/
│   ├── catalog.yaml                    # multi-document YAML
│   └── bundles.yaml                    # additional bundle blobs
└── ...                                 # one subdirectory per operator package
```

---

## FBC Document Types — The Hierarchy

Three schema types define the catalog structure:

```
olm.package                 ← Defines a package name and its channels
    └── olm.channel         ← Maps channels to bundles
            └── olm.bundle  ← Contains operator version and CSV
```

The tool parses all three and links them together.

---

## `olm.package` — Top Level

Defined in `packages.json`. Declares a package and lists its channels.

```json
{
  "schema": "olm.package",
  "name": "quay-operator",
  "channels": [{"name": "stable-3.17"}],
  "defaultChannel":     "stable-3.17"
}
```

Each package is an operator you can install on your cluster.

---

## `olm.channel` — Middle Layer

Defined in `configs/alpha/channels/`. Maps a channel name to its bundles.

```json
{
  "schema": "olm.channel",
  "name": "stable-3.17",
  "package": "quay-operator",
  "entries": [{"image": "quay.io/...@sha256:..."}]
}
```

A channel is a named path (e.g. `stable`, `stable-3.17`, `beta`) that users subscribe to.

---

## `olm.bundle` — Leaf Node

Each bundle references a **bundle container image** (e.g. `operator-bundle:v3.17.0`), which is not the operator image itself.

This bundle image contains:

- **ClusterServiceVersion (CSV)** — declares the operator, its versions, CRDs, dependencies
- **CRDs and CustomResources** — schemas and sample resources the operator installs
- **Deployment manifests** — how the operator runs on the cluster

```json
{
  "schema": "olm.bundle",
  "name": "quay-operator.v3.17.0",
  "package": "quay-operator",
  "image": "quay.io/.../quay-operator-bundle@sha256:...",
  "properties": [{"type": "olm.package", "value": {"name": "quay-operator", "version": "3.17.0"}}]
}
```

The bundle image is the installable unit — OLM pulls it, reads the CSV, and installs the operator.

---

## Version Resolution

How the tool finds all available versions per channel:

1. Walk every `olm.bundle` document
2. Extract version from the bundle's `olm.package` property
3. Fallback: regex on bundle filename (e.g. `v3.17.0`)
4. Deduplicate and naturally sort (`4.9` before `4.10`)

---

## Key Features

- **v1 & v2 output** — supports both `v1alpha2` and `v2alpha1` `oc-mirror` formats
- **Version comments** — `--version-comment` lists all versions per channel as YAML comments
- **min/max version** — `--min-max-version` auto-fills `minVersion` / `maxVersion` keys
- **TLS control** — `--tls-verify false` for internal registries
- **GPG bypass** — `--disable-signature-policy` for non-RHEL systems
- **Local mode** — `--configs /path` skips fetch/extract for already-extracted data

---

## Advanced Usage

Add version comments and min/max bounds:

```bash
./imagesetconfig-generator.py \
  -c registry.redhat.io/redhat/redhat-operator-index:v4.20 \
  --generate config.yaml --v2 \
  --version-comment --min-max-version
```

Generate from pre-extracted data in /tmp/redhat-operator-index_v4.20 :

```bash
./imagesetconfig-generator.py \
  -c my-catalog:v1 \
  --configs /tmp/redhat-operator-index_v4.20 \
  --generate offline-config.yaml --v1
```

---

## Testing

Tests use only Python3 stdlib + `pyyaml` and `podman` for pull and extraction.
No other external dependencies.

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Two tiers:
- **Unit tests** — FBC parsing and YAML generation against synthetic data
- **Real catalog tests** — against pinned public catalog clones for golden-file validation

---

## Resources

| Resource | Link |
|----------|------|
| Source code | `imagesetconfig-generator.py` |
| Design doc | `doc/design.md` |
| Test suite | `tests/` |
| TODO | `TODO.md` |
| oc-mirror docs | Openshift documentation |

---

## Questions?
