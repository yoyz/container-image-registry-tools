# Design: How an Operator Catalog Image Is Built (and How We Read It)

This document explains how Red Hat / OpenShift Operator catalog images are
constructed, what the `ImageSetConfiguration` generator does with them, and why
the tool is structured the way it is. Where behaviour matters for accuracy, we
cite the upstream OpenShift and Operator Framework documentation.

> References:
>
> - Operator Lifecycle Manager, **"File-based Catalogs"** reference:
>   <https://olm.operatorframework.io/docs/reference/file-based-catalogs/>
> - OpenShift, **"OLM packaging format"** (SQLite / declarative history):
>   <https://docs.openshift.com/container-platform/4.16/operators/understanding/olm-packaging-format.html>
> - OpenShift, **"Managing catalogs"** (catalog images / `oc-mirror`):
>   <https://docs.openshift.com/container-platform/4.16/operators/admin/olm-managing-catalogs.html>

## 1. What an Operator catalog is

An Operator catalog is a container image that packages metadata describing a set
of Kubernetes Operators. OLM (the Operator Lifecycle Manager) serves that
metadata to a cluster, which uses it to present installable operators
(`oc get packagemanifests`), resolve dependencies, and compute upgrade graphs.

The image itself is *just the metadata* — no operator code runs inside it. The
actual operator images are referenced by name; the cluster pulls them at install
time. This is exactly why a disconnected cluster needs the metadata plus a list
of the referenced images to mirror.

### The two catalog formats

| Format                            | Era               | Location                              | How the generator sees it |
|-----------------------------------|-------------------|---------------------------------------|---------------------------|
| SQLite (`packages.db`)            | ≤ OpenShift 4.15  | a database file at the image root     | not supported             |
| **File-Based Catalog (FBC)**      | OpenShift 4.16+   | plaintext files under `/configs/`     | supported                 |

FBC is the evolution of the old SQLite format: fully plaintext (JSON or YAML),
stored in an arbitrary directory hierarchy under `/configs/`. It is designed for
**editability, composability, and extensibility** — a catalog maintainer can
diff, validate, and merge catalogs with ordinary tooling. [^fbc-design]

[^fbc-design]: olm.operatorframework.io, "File-based Catalogs" →
    *Design* section. The primary design goal is to enable catalog editing,
    composability, and extensibility; the format is a "fully plaintext-based
    (JSON or YAML) evolution of the previous sqlite database format".

## 2. The FBC directory layout

`opm` (the Operator Package Manager CLI that builds catalogs) walks the catalog
root and loads every file it finds, recursing into subdirectories. The `Meta`
schema every blob must satisfy has four core fields:

```yaml
schema:     # required — identifies the blob type (e.g. "olm.package")
package:    # optional — which package this blob belongs to
name:       # optional — the object name
properties: # optional — arbitrary metadata (e.g. bundle versions, GVKs)
```

OLM defines the schema values the generator cares about:

- `olm.package` — package-level metadata (name, description, **defaultChannel**, icon).
- `olm.channel` — one channel of a package: the bundle entries that are members
  of the channel and their upgrade edges (`replaces`, `skips`, `skipRange`).
- `olm.bundle` — one individually installable version of an operator; carries the
  `image` location and `properties` (crucially, the `olm.package` property that
  pins the **package name + version**).

Each package in a catalog requires *exactly one* `olm.package` blob, *at least
one* `olm.channel` blob, and *one or more* `olm.bundle` blobs. [^fbc-schema]

[^fbc-schema]: olm.operatorframework.io, "File-based Catalogs" →
    *OLM-defined schemas*. "Each operator package in a catalog requires exactly
    one `olm.package` blob, at least one `olm.channel` blob, and one or more
    `olm.bundle` blobs."

### What the real catalog images look like

A Red Hat index image (`redhat-operator-index`, `certified-operator-index`,
`community-operators`) places the FBC root at `/configs/`. The layout is a
directory per operator package, and the files inside are **not** constrained to a
single shape — each file may be JSON or YAML, and a package may split its blobs
across several files. Real catalogs show all of these combinations:

```text
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

This is why the generator's parser selection is driven purely by file extension
and why the JSON reader must handle a stream of concatenated objects (see §3.1).

Each package directory typically holds a single `catalog.json` that is a stream
of **multiple concatenated JSON objects** — one per blob. Our own extraction of
`registry.redhat.io/redhat/certified-operator-index:v4.16` confirms this shape:
`/configs/<pkg>/catalog.json` with one `olm.package`, one or more `olm.channel`,
and many `olm.bundle` blobs back to back. [^extract-observed]

The public `redhat-openshift-ecosystem` repos that *build* those images store the
same content as YAML (`catalog.yaml` per package) — which is what the test
suite's pinned clones use. [^clones]

[^extract-observed]: Observed locally from `podman create` + `podman cp` of
    `/configs` from `certified-operator-index:v4.16`.
[^clones]: The test suite clones `community-operators-prod` and
    `certified-operators` (the source repos behind the images) at pinned commits,
    only checking out `catalogs/<version>`, and asserts the generator output is
    byte-identical to committed goldens.

## 3. How the generator deciphers the catalog

The generator (`imagesetconfig-generator.py`) does not talk to OLM or `opm`. It
reads the plaintext FBC directly and reconstructs the package/channel/version
structure. Three parsing steps mirror the three schemas.

### 3.1 File discovery and parser selection

`handle_parse_fbc` walks the config directory recursively. `_select_parser`
chooses a reader by extension:

- `.json` → `extract_json_objects`, a **concatenated-JSON decoder**. Because a
  `catalog.json` is several JSON documents in one file, a normal `json.load`
  would fail on the trailing bytes of the first object; the generator uses
  `json.JSONDecoder.raw_decode` repeatedly to peel objects off one at a time.
- `.yaml` / `.yml` → `yaml.safe_load_all`, which natively yields a stream of
  documents.
- anything else (e.g. `README.txt`) → skipped.

### 3.2 Document dispatch by schema

`_handle_doc` dispatches each decoded blob:

| Schema        | What is captured                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------------|
| `olm.package` | registers the package, records its `defaultChannel`                                                                    |
| `olm.channel` | registers the channel under its package, collects the **entry names** (the `name` of each entry, i.e. bundle names)    |
| `olm.bundle`  | maps the bundle **name → version** via the `olm.package` property (`value.packageName` + `value.version`)              |

### 3.3 Resolving versions

`olm.channel.entries[].name` references bundle names (e.g.
`amq-streams.v2.10.0`), but `oc-mirror` wants concrete versions. `_resolve_versions`
joins the two:

1. Look up the entry name in the bundle-name → version map built from
   `olm.bundle` blobs.
2. **Fallback**: if no bundle was seen (some catalogs omit bundles for a
   channel), the version is extracted from the bundle name with the regex
   `\.v(<version>)$` — so `amq-streams.v2.10.0` yields `2.10.0`.
3. Deduplicate and **natural-sort** (`natural_sort_key`), so `2.2.0` sorts
   before `2.10.0` (a plain lexical sort would put `2.10.0` first).

### 3.4 Emitting the `ImageSetConfiguration`

`write_image_set_config` converts the in-memory map into `oc-mirror` YAML:

```yaml
apiVersion: mirror.openshift.io/v2alpha1
kind: ImageSetConfiguration
mirror:
  operators:
  - catalog: registry.redhat.io/redhat/redhat-operator-index:v4.20
    packages:
    - name: quay-operator
      channels:
      - name: stable-3.17  # default
      defaultChannel: stable-3.17
```

Notable behaviours:

- Channels are naturally sorted; packages are alphabetically sorted.
- The `defaultChannel` (from `olm.package`) must exist in the channel list — if
  it doesn't (malformed catalog), the last channel is used as a safe fallback.
- v1 (`mirror.openshift.io/v1alpha2`) omits `defaultChannel`; v2
  (`mirror.openshift.io/v2alpha1`) includes it, since it is mandatory there.
- Optional `--version-comment` / `--min-max-version` annotate each channel with
  its full version list or a `minVersion`/`maxVersion` pair.

## 4. The pipeline (fetch → extract → generate)

```text
podman pull <catalog>        # fetch: get the catalog image
podman create <catalog>      # extract: make a stopped container from the image
podman cp <id>:/configs/. /tmp/<sanitized-catalog>/   # copy the FBC root out
<parse FBC> → <write YAML>   # generate: reverse-engineer the ImageSetConfiguration
```

1. **Fetch** — `handle_fetch` runs `podman pull`. Authentication failures surface
   directly from podman (with a `podman login` hint); the tool does **not** use
   `podman search` as an auth probe, since search can be anonymous where pull
   requires credentials. If the image is already in `podman images`, the tool
   suggests dropping `--fetch`. `--disable-signature-policy` writes a temporary
   `insecureAcceptAnything` policy file for systems missing the Red Hat GPG key.
2. **Extract** — `handle_extract` runs `podman create` (turning the image into a
   stopped container), copies `/configs/.` to
   `/tmp/<sanitized-catalog>/` (e.g. `registry_redhat_io_redhat_redhat-operator-index_v4_20`),
   then removes the container. `--tls-verify` is forwarded to `podman create`.
3. **Generate** — `handle_parse_fbc` + `write_image_set_config` (section 3). The
   output path is write-tested up front (`_check_output_writable`) so a bad
   `--generate` path fails before the long pull/extract work.

The three steps are independent and can be chained or run separately; `--configs`
points directly at an already-extracted tree to skip podman entirely.

## 5. Why the tests pin real catalogs

The FBC spec is permissive, and the generator must be robust to real-world
quirks. The test suite therefore runs against:

- **Synthetic fixtures** (`tests/fixtures/`) that each isolate one edge case:
  prefix-collision (`amq-streams` vs `amq-streams-console`), YAML-quoted channel
  names (`'3.15'`), and bundles without an `olm.package` property.
- **Pinned real catalogs** (`tests/helpers.py` `AUTO_CLONE_SOURCES`): the public
  `community-operators-prod` and `certified-operators` repos checked out at fixed
  commits. Because FBC is plaintext and version-controlled, a clone at a pinned
  commit is a reproducible snapshot of the catalog data the images are built
  from. Generated output is compared byte-for-byte against committed goldens.

Private-registry extracts (`/tmp/registry_redhat_io_redhat_*`) are treated as
**opportunistic** only — they exist on machines that already ran `--extract` and
can never be a release dependency.
