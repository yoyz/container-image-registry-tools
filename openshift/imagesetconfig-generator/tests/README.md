# Test Infrastructure

The test suite covers the two stages of the generator that do not require
`podman`: FBC parsing (`handle_parse_fbc`) and YAML generation
(`write_image_set_config`). The `podman`-dependent steps (`handle_fetch`,
`handle_extract`) are exercised with `subprocess.run` mocked out — they must
not be called for real in tests.

Tests run against the **real codebase** — `tests/helpers.py` loads
`imagesetconfig-generator.py` via `importlib` (the filename contains a hyphen,
so it cannot be imported normally) and every test calls the actual functions.

## Layout

```
tests/
├── helpers.py            # module loading, fixture/golden paths, catalog discovery
├── test_basic_parsing.py # unit tests on synthetic FBC fixtures
├── test_real_catalog.py  # high-level tests on real extracted catalogs
├── fixtures/             # small hand-written FBC configs
│   ├── prefix-collision/     amq-streams vs amq-streams-console (exact-match regression)
│   ├── quoted-channel/       YAML-quoted channel name ('3.15')
│   └── fallback-version/     bundle w/o olm.package + non-target files (.txt)
└── golden/               # expected output (encode current behavior)
    ├── combined-v1.yaml      synthetic fixture, full v1 output
    ├── combined-v2.yaml      synthetic fixture, full v2 output
    └── real/                 pinned public catalogs, all output variants
        ├── community-operators-prod_v4.20-v1.yaml
        ├── community-operators-prod_v4.20-v2.yaml
        ├── ... (v2-minmax, v2-comments, v2-minmax-comments)
        └── certified-operators_v4.20-*.yaml
```

## Running the Tests

Requires only the Python standard library (`unittest`) and `pyyaml` — no
`pytest`, no `podman`.

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

### Basic tier only

```bash
python3 -m unittest tests.test_basic_parsing
```

### Real-catalog tier

`test_real_catalog.py` discovers catalogs in this order:

1. `$CATALOG_DIR` (explicit path)
2. `/tmp/registry_redhat_io_redhat_*` — standard `--extract` output, i.e.
   catalogs pulled from the **private registry**. **Opportunistic only.** These
   directories only exist on machines where someone already ran `--extract`
   against a private registry, and `podman pull` is not guaranteed to work on
   another system. They are the real target of this tool, but a release must
   **never** depend on them.
3. Public catalog clones: `community-operators-prod` and `certified-operators`
   (see below)

If none are usable the whole tier is skipped, so the suite stays green on
machines without extracted catalogs. To run against a specific one:

```bash
CATALOG_DIR=/tmp/registry_redhat_io_redhat_redhat-operator-index_v4_20 \
  python3 -m unittest discover -s tests -p 'test_*.py'
```

### Release gate

The deterministic release check runs only the basic tier plus the public
clones — sources that exist on any machine with `git` and network access:

```bash
SKIP_PRIVATE_REGISTRY_CATALOGS=1 \
  python3 -m unittest discover -s tests -p 'test_*.py'
```

This never requires a private-registry pull. The opportunistic
`/tmp/registry_redhat_io_redhat_*` dirs are simply not scanned, so the release
result does not depend on which machine it runs on. Omit the flag to also
exercise the private-registry catalogs when they happen to be present.

### Public catalog clones (no private registry needed)

To avoid depending on a private registry pull, the real-catalog tier also runs
against public, versioned sources of FBC data — the official Red Hat
`redhat-openshift-ecosystem` repos that build the `community-operator-index`
and `certified-operator-index` images:

- `community-operators-prod`
- `certified-operators`

On first run the suite clones each, shallow + sparse, to:

```
/tmp/imagesetconfig-generator/test/community-operators-prod
/tmp/imagesetconfig-generator/test/certified-operators
```

only checking out `catalogs/v4.20` (each ~30-45 MB), so the whole tree is never
downloaded.

**Pinned data for reproducibility.** Each source is checked out at a fixed
commit (recorded in `tests/helpers.py` under `AUTO_CLONE_SOURCES` as `sha`,
with `pinned_date` for reference), so every run — now and later — exercises the
exact same set of operators, independent of upstream changes:

| Source | Pinned commit | Pinned date |
|---|---|---|
| `community-operators-prod` | `f6bcb4efa13d0b4d0575f719f8f3e1959fe95a71` | 2026-08-11 |
| `certified-operators` | `b2c2d5716e6ad1f262160348637d6f29126aac1a` | 2026-08-11 |

- **Reuse, don't re-clone:** an existing clone is reused as-is only when it is
  already at the pinned commit (verified via `git rev-parse HEAD`). A missing,
  broken, or outdated clone — e.g. one from an earlier run against `main` — is
  re-created at the pin. Once pinned, subsequent runs reuse it instantly.
- **Graceful degradation:** if `git` is missing or there is no network, the
  tier warns and skips rather than failing the suite.

**Bumping the pinned data:** to move to newer data, resolve a fresh commit from
`https://api.github.com/repos/redhat-openshift-ecosystem/<repo>/commits/main`,
update its `sha`/`pinned_date` in `AUTO_CLONE_SOURCES`, then delete the stale
clone dir under `/tmp` (e.g. `rm -rf /tmp/imagesetconfig-generator/test/community-operators-prod`)
so it is re-created at the new commit. **Regenerate the goldens** for the new
tree (see below) before committing, since the expected output changes with the
data.

### Output reproducibility guarantee

For the pinned public clones, the committed goldens under `tests/golden/real/`
are the guarantee that running `imagesetconfig-generator.py` against the pinned
tree always produces the same `imagesetconfig.yaml`:

```
tests/golden/real/community-operators-prod_v4.20-v1.yaml
tests/golden/real/community-operators-prod_v4.20-v2.yaml
tests/golden/real/community-operators-prod_v4.20-v2-minmax.yaml
tests/golden/real/community-operators-prod_v4.20-v2-comments.yaml
tests/golden/real/community-operators-prod_v4.20-v2-minmax-comments.yaml
tests/golden/real/certified-operators_v4.20-v1.yaml
tests/golden/real/certified-operators_v4.20-v2.yaml
tests/golden/real/certified-operators_v4.20-v2-minmax.yaml
tests/golden/real/certified-operators_v4.20-v2-comments.yaml
tests/golden/real/certified-operators_v4.20-v2-minmax-comments.yaml
```

Each pinned catalog is parsed and every output variant is generated with the
**real** generator code, then compared byte-for-byte against these files:
`v1`, `v2`, `v2 --min-max-version`, `v2 --version-comment`, and the combined
`v2 --version-comment --min-max-version`.
- Because the tree is pinned and the generator is deterministic, the comparison
  is stable: it only changes when someone intentionally changes the generator's
  output behavior (a failing diff then forces a deliberate golden regeneration).
- Private-registry extracts have no goldens — they are not reproducible, so
  their golden tests are skipped.

To regenerate the goldens after bumping a pin (or changing output formatting):

```bash
python3 - <<'EOF'
import sys, os, contextlib, io
sys.path.insert(0, 'tests')
from helpers import load_generator, golden_path
mod = load_generator()
FAKE = 'example.com/operators/real-catalog:v1'
variants = [('v1', 'v1', {}),
            ('v2', 'v2', {}),
            ('v2-minmax', 'v2', {'min_max_version': True}),
            ('v2-comments', 'v2', {'version_comments': True}),
            ('v2-minmax-comments', 'v2', {'version_comments': True, 'min_max_version': True})]
for label, d in [('community-operators-prod_v4.20',
                  '/tmp/imagesetconfig-generator/test/community-operators-prod/catalogs/v4.20'),
                 ('certified-operators_v4.20',
                  '/tmp/imagesetconfig-generator/test/certified-operators/catalogs/v4.20')]:
    with contextlib.redirect_stdout(io.StringIO()):
        pm = mod.handle_parse_fbc(d)
    for suffix, version, kwargs in variants:
        with contextlib.redirect_stdout(io.StringIO()):
            mod.write_image_set_config(golden_path('real', f'{label}-{suffix}.yaml'),
                                       FAKE, pm, version=version, **kwargs)
EOF
```

Review the diff with `git diff tests/golden/real/` before committing.

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `CATALOG_DIR` | — | Run only against this explicit catalog path |
| `SKIP_PRIVATE_REGISTRY_CATALOGS` | unset | Set to `1` to skip the opportunistic `/tmp/registry_redhat_io_redhat_*` dirs (used by the release gate) |
| `CATALOG_VERSION` | `v4.20` | Version checked out on fresh clones |
| `COMMUNITY_CATALOGS_URL` | `https://github.com/redhat-openshift-ecosystem/community-operators-prod.git` | Community repo to clone |
| `COMMUNITY_CATALOGS_DIR` | `/tmp/imagesetconfig-generator/test/community-operators-prod` | Where the community clone lives |
| `CERTIFIED_CATALOGS_URL` | `https://github.com/redhat-openshift-ecosystem/certified-operators.git` | Certified repo to clone |
| `CERTIFIED_CATALOGS_DIR` | `/tmp/imagesetconfig-generator/test/certified-operators` | Where the certified clone lives |
| `SKIP_COMMUNITY_CLONE` | unset | Set to `1` to skip the community clone |
| `SKIP_CERTIFIED_CLONE` | unset | Set to `1` to skip the certified clone |
| `SKIP_AUTO_CLONES` | unset | Set to `1` to disable all auto-cloning |

## What Each Tier Validates

**Basic (`test_basic_parsing.py`)**
- Prefix-collision regression: `amq-streams` and `amq-streams-console` stay
  separate packages with their own channels and versions.
- Natural sort: `2.2.0 < 2.10.0 < 2.11.0` (lexicographic would order wrongly).
- YAML-quoted channel names (`'3.15'`): collected and matched as defaults.
- Version fallback: a bundle without an `olm.package` property resolves its
  version from the bundle name via the `\.v<version>` regex.
- Non-target files (`.txt`, etc.) are ignored without errors.
- Golden files: full v1/v2 output must match `tests/golden/` byte-for-byte,
  covering the `# default` / `# versions` comment formatting and
  `minVersion`/`maxVersion` / `defaultChannel` keys.

**Real catalog (`test_real_catalog.py`)**
- Structural invariants over the whole catalog: every package has at least one
  channel, every channel has at least one version, the default channel is
  present in the channel list, and versions are naturally sorted.
- Generated v1/v2 output parses as valid YAML with the expected apiVersion and
  package count; v2 entries carry a `defaultChannel` that is in their channels;
  `--min-max-version` and `--version-comment` produce the expected keys/lines.
- **Reproducibility:** for the pinned public clones, generated v1/v2 output is
  byte-identical to the committed goldens in `tests/golden/real/` — the same
  tree always yields the same `imagesetconfig.yaml`.
- Known-package regression on Red Hat indexes: `amq-streams` must not absorb
  the console-only `alpha` channel (tests are skipped for catalogs lacking
  these packages, e.g. the certified index or the community catalog).

The invariants run against every discovered catalog, so the public clones act
as permanently available real-data checks even when no private-registry catalog
has been extracted on the machine.

## Regenerating Golden Files

`tests/golden/` encode the current formatting behavior. After an intentional
formatting change, regenerate them by running the generator against the
combined fixture (union of all `tests/fixtures/`):

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, 'tests')
from helpers import load_generator, assemble_combined_config, golden_path
import tempfile, os
mod = load_generator()
tmp = tempfile.mkdtemp()
combined = assemble_combined_config(tmp)
for v in ('v1', 'v2'):
    mod.write_image_set_config(golden_path(f'combined-{v}.yaml'),
                               'example.com/operators/test-catalog:v1',
                               mod.handle_parse_fbc(combined), version=v)
EOF
```

Verify the diff with `git diff tests/golden/` before committing.
