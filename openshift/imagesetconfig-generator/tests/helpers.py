"""Shared helpers for the imagesetconfig-generator test suite.

The generator script has a hyphen in its filename, so it cannot be imported
directly; ``load_generator()`` loads it under a module name that Python accepts.
"""

import glob
import importlib.util
import os
import shutil
import subprocess
import tempfile

TESTS_DIR = os.path.dirname(__file__)
SCRIPT_PATH = os.path.join(os.path.dirname(TESTS_DIR), 'imagesetconfig-generator.py')
FIXTURES_DIR = os.path.join(TESTS_DIR, 'fixtures')
GOLDEN_DIR = os.path.join(TESTS_DIR, 'golden')
REAL_CATALOG_DIR = os.environ.get('CATALOG_DIR')

CATALOG_VERSION = os.environ.get('CATALOG_VERSION', 'v4.20')

# Public, auto-cloned sources of real FBC catalog data. Each entry has:
#   name        — label used in messages and class names
#   url         — git remote to clone (env-overridable)
#   clone_dir   — where the clone lives under /tmp (env-overridable)
#   sha         — exact commit to check out, so every test run sees the same
#                 data regardless of upstream changes (pinning)
#   pinned_date — when that commit was captured, for reference/bumping
#   skip_env    — env var that, when set, disables cloning this source
#
# To bump a pin: resolve a new commit on main via the GitHub API
#   https://api.github.com/repos/redhat-openshift-ecosystem/<repo>/commits/main
# update its `sha` (and `pinned_date`) here, and delete the existing clone dir
# under /tmp so it is re-created at the new commit.
AUTO_CLONE_SOURCES = [
    {
        'name': 'community-operators-prod',
        'url': os.environ.get(
            'COMMUNITY_CATALOGS_URL',
            'https://github.com/redhat-openshift-ecosystem/community-operators-prod.git',
        ),
        'clone_dir': os.environ.get(
            'COMMUNITY_CATALOGS_DIR',
            '/tmp/imagesetconfig-generator/test/community-operators-prod',
        ),
        'sha': 'f6bcb4efa13d0b4d0575f719f8f3e1959fe95a71',
        'pinned_date': '2026-08-11',
        'skip_env': 'SKIP_COMMUNITY_CLONE',
    },
    {
        'name': 'certified-operators',
        'url': os.environ.get(
            'CERTIFIED_CATALOGS_URL',
            'https://github.com/redhat-openshift-ecosystem/certified-operators.git',
        ),
        'clone_dir': os.environ.get(
            'CERTIFIED_CATALOGS_DIR',
            '/tmp/imagesetconfig-generator/test/certified-operators',
        ),
        'sha': 'b2c2d5716e6ad1f262160348637d6f29126aac1a',
        'pinned_date': '2026-08-11',
        'skip_env': 'SKIP_CERTIFIED_CLONE',
    },
]

_auto_clone_cache = {}


def load_generator():
    """Import imagesetconfig-generator.py as a regular module."""
    spec = importlib.util.spec_from_file_location('imagesetconfig_generator', SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fixture_path(*parts):
    return os.path.join(FIXTURES_DIR, *parts)


def golden_path(*parts):
    return os.path.join(GOLDEN_DIR, *parts)


def assemble_combined_config(tmp_dir):
    """Copy all synthetic fixtures into a single combined config directory.

    Returns the path to the combined config dir. The package set is the union
    of every fixture, so golden outputs cover all handling paths at once.
    """
    combined = os.path.join(tmp_dir, 'combined-configs')
    os.makedirs(combined)
    for root, _, files in os.walk(FIXTURES_DIR):
        for file in files:
            src = os.path.join(root, file)
            rel = os.path.relpath(src, FIXTURES_DIR)
            dst = os.path.join(combined, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    return combined


def _version_dirs(catalogs_root):
    """Return the version directories (e.g. v4.20) inside a cloned catalog tree."""
    if not os.path.isdir(catalogs_root):
        return []
    return sorted(d for d in os.listdir(catalogs_root)
                  if os.path.isdir(os.path.join(catalogs_root, d)))


def _version_is_usable(version_dir):
    """A version dir is usable if it contains at least one operator with a
    parseable FBC file."""
    if not os.path.isdir(version_dir):
        return False
    for entry in os.listdir(version_dir):
        sub = os.path.join(version_dir, entry)
        if not os.path.isdir(sub):
            continue
        try:
            files = os.listdir(sub)
        except OSError:
            continue
        if any(f.endswith(('.json', '.yaml', '.yml')) for f in files):
            return True
    return False


def _clone_is_pinned(source):
    """True if an existing clone is checked out at the pinned commit."""
    try:
        out = subprocess.run(
            ['git', '-C', source['clone_dir'], 'rev-parse', 'HEAD'],
            check=True, capture_output=True, text=True)
        return out.stdout.strip() == source['sha']
    except Exception:
        return False


def _clone_catalog_source(source):
    """Clone a catalog source at its pinned commit (shallow + sparse).

    Only the requested version under ``catalogs/`` is checked out to keep the
    clone small. Raises on failure; callers treat errors as "source unavailable".
    """
    clone_dir = source['clone_dir']
    os.makedirs(os.path.dirname(clone_dir), exist_ok=True)
    if os.path.isdir(clone_dir):
        shutil.rmtree(clone_dir)
    subprocess.run(['git', 'init', '-q', clone_dir],
                   check=True, capture_output=True, text=True)
    subprocess.run(['git', '-C', clone_dir, 'remote', 'add', 'origin', source['url']],
                   check=True, capture_output=True, text=True)
    subprocess.run(['git', '-C', clone_dir, 'fetch', '-q', '--depth', '1',
                    '--filter=blob:none', 'origin', source['sha']],
                   check=True, capture_output=True, text=True)
    subprocess.run(['git', '-C', clone_dir, 'sparse-checkout', 'init', '--cone'],
                   check=True, capture_output=True, text=True)
    subprocess.run(['git', '-C', clone_dir, 'sparse-checkout', 'set',
                    f'catalogs/{CATALOG_VERSION}'],
                   check=True, capture_output=True, text=True)
    subprocess.run(['git', '-C', clone_dir, 'checkout', '-q', source['sha']],
                   check=True, capture_output=True, text=True)


def _ensure_catalog_source(source):
    """Make sure a usable, pinned clone of one catalog source exists under /tmp.

    The data is reproducible: the clone is always checked out at the commit
    recorded in ``source['sha']``, so every test run sees the same set of
    operators regardless of upstream changes. An existing clone is reused only
    when it is already at that pinned commit; a missing, broken, or outdated
    clone (e.g. one from an earlier run against ``main``) is (re)created at the
    pin. Failures (missing git, no network) degrade gracefully to "unavailable".

    Returns the path to the ``catalogs/`` directory, or None.
    """
    name = source['name']
    if name in _auto_clone_cache:
        return _auto_clone_cache[name] or None

    _auto_clone_cache[name] = False  # in-flight guard against recursion
    catalogs_root = os.path.join(source['clone_dir'], 'catalogs')
    if _version_dirs(catalogs_root) and _clone_is_pinned(source):
        _auto_clone_cache[name] = catalogs_root
        return catalogs_root

    try:
        _clone_catalog_source(source)
    except Exception as e:
        print(f"WARN: {name} catalogs unavailable ({e}) — skipping those tests")
        return None

    catalogs_root = os.path.join(source['clone_dir'], 'catalogs')
    if _version_dirs(catalogs_root):
        _auto_clone_cache[name] = catalogs_root
        return catalogs_root
    return None


def auto_cloned_catalog_dirs():
    """Return usable version directories from all auto-cloned catalog sources."""
    dirs = []
    for source in AUTO_CLONE_SOURCES:
        if os.environ.get('SKIP_AUTO_CLONES'):
            break
        if os.environ.get(source['skip_env']):
            continue
        catalogs_root = _ensure_catalog_source(source)
        if catalogs_root:
            dirs.extend(
                os.path.join(catalogs_root, v)
                for v in _version_dirs(catalogs_root)
                if _version_is_usable(os.path.join(catalogs_root, v)))
    return dirs


def catalog_source_label(catalog_dir):
    """Return a stable label for an auto-cloned catalog dir, or None otherwise.

    The label (e.g. ``community-operators-prod_v4.20``) identifies the pinned
    source + version and keys the committed golden outputs. Returns None for
    directories that are not from an auto-cloned source (e.g. private-registry
    extracts), since those are not reproducible and have no goldens.
    """
    clone_root = os.path.dirname(os.path.dirname(catalog_dir))
    for source in AUTO_CLONE_SOURCES:
        if os.path.realpath(source['clone_dir']) == os.path.realpath(clone_root):
            return f"{source['name']}_{os.path.basename(catalog_dir)}"
    return None


def find_real_catalogs():
    """Locate real FBC catalog directories to run high-level tests against.

    Order of preference:
      1. $CATALOG_DIR (explicit)
      2. /tmp/registry_redhat_io_redhat_* (standard --extract output, i.e.
         catalogs pulled from the private registry). Opportunistic only: these
         only exist on machines that have already run --extract against a
         private registry, so they must never be relied on for a release gate.
         Set SKIP_PRIVATE_REGISTRY_CATALOGS=1 to exclude them explicitly.
      3. Auto-cloned public catalog sources under /tmp (community-operators-prod,
         certified-operators; set SKIP_AUTO_CLONES=1 or per-source SKIP_*_CLONE=1
         to disable)

    Returns a sorted list of absolute paths, or [] if none are usable.
    """
    candidates = []
    if REAL_CATALOG_DIR:
        candidates.append(REAL_CATALOG_DIR)
    else:
        if not os.environ.get('SKIP_PRIVATE_REGISTRY_CATALOGS'):
            candidates = sorted(glob.glob('/tmp/registry_redhat_io_redhat_*'))
        candidates.extend(auto_cloned_catalog_dirs())
    return [c for c in candidates if os.path.isdir(c)]


def make_temp_config_dir():
    """Return a temp dir and a cleanup function; used to isolate outputs."""
    tmp = tempfile.TemporaryDirectory()
    return tmp.name, tmp.cleanup
