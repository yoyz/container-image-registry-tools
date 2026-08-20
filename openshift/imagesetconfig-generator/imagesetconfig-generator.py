#!/usr/bin/env python3

import os
import json
import yaml
import sys
import argparse
import re
import subprocess
import shutil
import signal
import time

# --- Global Configuration ---
VERSION = "0.2.0"

# TODO:
# 1. [FIXED] write_image_set_config: the '# default' comment (and _default stripping)
#    relied on substring matching and could match the wrong package/channel (e.g. a
#    package whose name is a prefix of another, like amq-streams vs amq-streams-console).
#    Now uses exact name matching via regex + op_defaults dict. Also fixed YAML-quoted
#    channel names (e.g. '3.15') breaking lookups.
# 2. [DONE] README example output now matches reality (no '_default:' lines; the
#    '# default' annotation is appended as a trailing comment).
# 3. [DONE] write_image_set_config no longer stores the '_default' intermediate on
#    every entry; the default-channel marker is computed directly via op_defaults.
# 4. [DONE] handle_extract now forwards '--tls-verify' to 'podman create'.
#    handle_fetch no longer uses 'podman search' as an auth pre-check; the pull
#    itself surfaces auth errors and prints a 'podman login' hint on failure.

# --- Helper Utilities ---

def natural_sort_key(s):
    """Sorts strings naturally (e.g., release-2.2 < release-2.11)."""
    return [int(text) if text.isdigit() else text.lower() for text in re.split('([0-9]+)', s)]

def extract_json_objects(text):
    """Generator for concatenated JSON objects (v4.16+ FBC format)."""
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace(): pos += 1
        if pos >= len(text): break
        try:
            obj, index = decoder.raw_decode(text[pos:])
            pos += index
            yield obj
        except json.JSONDecodeError:
            pos += 1

def get_safe_dirname(image_name):
    """Sanitizes image URL for use as a directory name in /tmp."""
    return re.sub(r'[:/.]', '_', image_name)

def timeout_handler(signum, frame):
    print(f"\n\nERROR: Command timed out! (Limit exceeded)")
    sys.exit(1)

def str2bool(v):
    if isinstance(v, bool): return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'): return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'): return False
    else: raise argparse.ArgumentTypeError('Boolean value expected.')

def _check_output_writable(output_file):
    """Fail fast if the output file cannot be written, before doing real work.

    Opens the file for append (creates it if missing); the real write later
    overwrites it with 'w'. Exits with a clear error instead of a traceback
    partway through fetch/extract/generate.
    """
    try:
        with open(output_file, 'a'):
            pass
    except OSError as e:
        print(f"\n[!] ERROR: Cannot write output file {output_file}: {e}")
        print("    Check the path is a writable location (e.g. your home or /tmp).")
        sys.exit(1)

# --- Core Functional Blocks ---

def _image_exists_locally(catalog):
    """True if the catalog image reference is already present in podman."""
    try:
        out = subprocess.run(['podman', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
                             capture_output=True, text=True, check=True)
        return catalog in out.stdout.splitlines()
    except Exception:
        return False

def resolve_catalog_digest(catalog):
    """Return the catalog's pinned digest reference ('<catalog>@sha256:...').

    Resolved from the locally stored image (first RepoDigest), so the exact
    content backing a tag can be reproduced even after the tag is retagged
    upstream. Returns None if the image is not present locally or podman is
    unavailable — callers should treat that as non-fatal.
    """
    try:
        out = subprocess.run(
            ['podman', 'image', 'inspect', '--format', '{{index .RepoDigests 0}}', catalog],
            capture_output=True, text=True, check=True)
        digest_ref = out.stdout.strip()
        if digest_ref:
            return digest_ref
    except Exception:
        pass
    return None

def handle_fetch(catalog, tls_verify, timeout, disable_sig):
    """Pulls the catalog image via podman.

    Auth failures surface directly from the pull (no separate `podman search`
    pre-check — that was a poor auth probe that passed for registries where
    search is anonymous but pull requires credentials).
    """
    registry = catalog.split('/')[0]
    print(f"--- Fetching {catalog} (Timeout: {timeout}s) ---")
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    tmp_policy = None
    try:
        pull_cmd = ['podman', 'pull', f'--tls-verify={str(tls_verify).lower()}', catalog]
        if disable_sig:
            print("--- Overriding GPG signature policy ---")
            tmp_policy = f"/tmp/allow_all_{int(time.time())}.json"
            with open(tmp_policy, 'w') as f:
                json.dump({"default": [{"type": "insecureAcceptAnything"}]}, f)
            pull_cmd.extend(['--signature-policy', tmp_policy])

        try:
            subprocess.run(pull_cmd, check=True)
        except subprocess.CalledProcessError:
            print(f"\n[!] ERROR: Podman failed to pull {catalog}.")
            print(f"    If the registry requires credentials, run: podman login {registry}")
            if _image_exists_locally(catalog):
                print(f"    The image {catalog} is already present in 'podman images';")
                print(f"    re-run without --fetch to use the local copy.")
            sys.exit(1)
    finally:
        signal.alarm(0)
        if tmp_policy and os.path.exists(tmp_policy):
            os.remove(tmp_policy)

def handle_extract(catalog, dest_path, tls_verify=True):
    """Creates temporary container to 'cp' the /configs directory out."""
    container_id = None
    try:
        print(f"--- Extracting /configs to {dest_path} ---")
        create_cmd = ['podman', 'create', f'--tls-verify={str(tls_verify).lower()}', catalog]
        container_id = subprocess.run(create_cmd, capture_output=True, text=True, check=True).stdout.strip()
        if os.path.exists(dest_path): shutil.rmtree(dest_path)
        os.makedirs(dest_path)
        subprocess.run(['podman', 'cp', f"{container_id}:/configs/.", dest_path], check=True)
    finally:
        if container_id:
            subprocess.run(['podman', 'rm', '-f', container_id], capture_output=True)

def _make_pkg_entry():
    """Factory for the per-package data structure."""
    return {"channels": set(), "default": None, "versions": {}, "display": None}

def _select_parser(filename):
    """Return a parser for an FBC file (by extension), or None if not a target."""
    if filename.endswith('.json'):
        return lambda f: extract_json_objects(f.read())
    elif filename.endswith(('.yaml', '.yml')):
        return lambda f: yaml.safe_load_all(f)
    return None

def _handle_doc(doc, pkg_map, bundle_versions, verbose):
    """Dispatch a single FBC document to the right schema handler."""
    if doc.get('schema') == 'olm.package':
        name = doc.get('name')
        if name:
            if name not in pkg_map: pkg_map[name] = _make_pkg_entry()
            pkg_map[name]["default"] = doc.get('defaultChannel')
            if verbose:
                print(f"{'PACKAGE':<12} | {name:<35} | Default: {doc.get('defaultChannel')}")
    elif doc.get('schema') == 'olm.channel':
        pkg = doc.get('package')
        chan = doc.get('name')
        if pkg and chan:
            if pkg not in pkg_map: pkg_map[pkg] = _make_pkg_entry()
            if chan not in pkg_map[pkg]["channels"]:
                pkg_map[pkg]["channels"].add(chan)
                pkg_map[pkg]["versions"][chan] = []
                if verbose:
                    print(f"{'CHANNEL':<12} | {pkg:<35} | -> {chan}")
            for entry in (doc.get('entries') or []):
                ename = entry.get('name')
                if ename and ename not in pkg_map[pkg]["versions"][chan]:
                    pkg_map[pkg]["versions"][chan].append(ename)
    elif doc.get('schema') == 'olm.bundle':
        name = doc.get('name')
        if name:
            pkg_ref = None
            for prop in (doc.get('properties') or []):
                ptype = prop.get('type')
                if ptype == 'olm.package':
                    bundle_versions[name] = prop.get('value', {}).get('version')
                    pkg_ref = pkg_ref or (prop.get('value', {}).get('packageName')
                                          or doc.get('package'))
                elif ptype == 'olm.csv.metadata':
                    pkg = pkg_ref or doc.get('package')
                    display = prop.get('value', {}).get('displayName')
                    if pkg and display:
                        if pkg not in pkg_map: pkg_map[pkg] = _make_pkg_entry()
                        if not pkg_map[pkg]["display"]:
                            pkg_map[pkg]["display"] = display

def _resolve_versions(pkg_map, bundle_versions):
    """Map channel entry names to bundle versions, naturally sorted."""
    for pkg in pkg_map:
        for chan in pkg_map[pkg]["versions"]:
            versions = set()
            for ename in pkg_map[pkg]["versions"][chan]:
                v = bundle_versions.get(ename)
                if not v:
                    m = re.search(r'\.v([0-9][^/]*)$', ename)
                    v = m.group(1) if m else ename
                if v: versions.add(v)
            pkg_map[pkg]["versions"][chan] = sorted(versions, key=natural_sort_key)

def handle_parse_fbc(config_dir, verbose=False):
    """Walks the config directory and builds a map of packages and channels.

    Returns a dict of pkg -> {"channels": set, "default": str,
    "versions": {channel: [sorted versions]}}. Versions are resolved from the
    'olm.package' property of each bundle (falling back to the bundle name).
    """
    pkg_map = {}
    bundle_versions = {}
    if verbose:
        print(f"\n{'STATUS':<12} | {'OPERATOR':<35} | {'CHANNEL/VERSION'}")
        print("-" * 80)
    for root, _, files in os.walk(config_dir):
        for file in files:
            parser = _select_parser(file)
            if not parser:
                continue
            if verbose:
                print(f"Reading {os.path.join(root, file)} ...", end='', flush=True)
                print(" OK")
            try:
                with open(os.path.join(root, file), 'r') as f:
                    for doc in parser(f):
                        if isinstance(doc, dict):
                            _handle_doc(doc, pkg_map, bundle_versions, verbose)
            except Exception as e:
                if verbose: print(f" FAIL ({e})")
                else: print(f"Warning: Could not parse {file}: {e}")

    _resolve_versions(pkg_map, bundle_versions)
    return pkg_map

def _format_digest_comment(digest_ref):
    """Return comment line(s) describing a pinned catalog digest reference.

    Keeps every line under 80 chars by folding the long sha256 hex onto a
    continuation line, e.g.:

        # catalog: registry.redhat.io/redhat/redhat-operator-index@sha256:
        #   7ee16003e0e7e13e0905fca1a981dab22cfe245f5a4e038b420be50dc624a9e5

    If the reference is short enough it is emitted on a single line.
    """
    prefix = "  # catalog: "
    tail = digest_ref
    if len(prefix) + len(tail) <= 80:
        return [prefix + tail]
    if '@sha256:' in digest_ref:
        repo, hexpart = digest_ref.rsplit('@sha256:', 1)
        return [f"{prefix}{repo}@sha256:", f"  #   {hexpart}"]
    return [prefix + tail]

def write_image_set_config(output_file, catalog, pkg_map, version='v1', version_comments=False, min_max_version=False, catalog_digest=None):
    """Generates the YAML file with version-specific validation and formatting.

    If version_comments is True, a '# versions: ...' comment is emitted below
    each channel listing the available versions.
    If min_max_version is True, each channel gets 'minVersion'/'maxVersion' keys
    (first/last of the channel's sorted versions) instead of the comment.
    If catalog_digest is given, a '# catalog: <digest>' comment is emitted below
    the catalog line so the exact image content can be reproduced via pull.
    """
    op_list = []
    op_defaults = {}
    for pkg in sorted(pkg_map.keys()):
        data = pkg_map[pkg]
        sorted_chans = sorted(list(data["channels"]), key=natural_sort_key)
        if not sorted_chans: continue

        # Ensure defaultChannel is present in the channel list for v2 compliance
        actual_default = data["default"]
        if actual_default not in sorted_chans:
            actual_default = sorted_chans[-1]

        channels = [{"name": c} for c in sorted_chans]
        if min_max_version:
            for ch in channels:
                versions = data.get("versions", {}).get(ch["name"])
                if versions:
                    ch["minVersion"] = versions[0]
                    ch["maxVersion"] = versions[-1]

        pkg_entry = {"name": pkg, "channels": channels}
        if version == 'v2': pkg_entry["defaultChannel"] = actual_default
        op_defaults[pkg] = actual_default
        op_list.append(pkg_entry)

    api_version = "mirror.openshift.io/v2alpha1" if version == 'v2' else "mirror.openshift.io/v1alpha2"
    config = {"apiVersion": api_version, "kind": "ImageSetConfiguration", "mirror": {"operators": [{"catalog": catalog, "packages": op_list}]}}
    raw_yaml = yaml.dump(config, default_flow_style=False, sort_keys=False)

    final_lines = []
    current_pkg = None
    current_default = None
    for line in raw_yaml.splitlines():
        pkg_line = re.match(r'^ {4}- name: (.+)$', line)
        chan_line = re.match(r'^ {6}- name: (.+?)(\s*#.*)?$', line)
        if pkg_line and "channels:" not in line:
            pkg_name = pkg_line.group(1).strip().strip("'\"")
            if pkg_name in op_defaults:
                current_pkg = pkg_name
                current_default = op_defaults[pkg_name]
        if chan_line:
            chan = chan_line.group(1).strip().strip("'\"")
            if current_default and chan == current_default:
                line = line.rstrip() + "  # default"
        final_lines.append(line)
        if re.match(r'^ {2}operators:', line) and catalog_digest:
            final_lines.extend(_format_digest_comment(catalog_digest))
        if version_comments and current_pkg and chan_line:
            versions = pkg_map[current_pkg].get("versions", {}).get(chan)
            if versions:
                final_lines.append(f"      # versions: {', '.join(versions)}")

    with open(output_file, 'w') as f: f.write("\n".join(final_lines))
    print(f"\n--- SUCCESS: Generated {output_file} (Format: {version}) ---")

def handle_list_operators(catalog, pkg_map, output_file=None):
    """Print (or write) an operator table mirroring `oc-mirror list operators`.

    Columns: NAME, DISPLAY NAME, DEFAULT CHANNEL. Column widths are computed
    from the widest value so rows align regardless of package name length. The
    DISPLAY NAME is taken from the bundle's 'olm.csv.metadata' displayName when
    present; otherwise a '-' placeholder is used. Results are naturally sorted
    by operator name. If output_file is given the table is written there,
    otherwise it is printed to stdout.
    """
    rows = []
    for pkg in sorted(pkg_map.keys()):
        data = pkg_map[pkg]
        if not data["channels"]:
            continue
        default = data["default"]
        if default not in data["channels"]:
            default = sorted(data["channels"], key=natural_sort_key)[-1]
        rows.append([pkg, data.get("display") or "-", default or "-"])

    if not rows:
        print("No operators found.")
        return

    headers = ["NAME", "DISPLAY NAME", "DEFAULT CHANNEL"]
    widths = []
    for col in range(3):
        widths.append(max(len(headers[col]), max(len(r[col]) for r in rows)))

    def fmt(r):
        return f"{r[0]:<{widths[0]+2}}{r[1]:<{widths[1]+2}}{r[2]}"

    lines = [fmt(headers)]
    lines.extend(fmt(r) for r in rows)
    text = "\n".join(lines)

    if output_file:
        with open(output_file, 'w') as f: f.write(text + "\n")
        print(f"--- SUCCESS: Wrote operator list to {output_file} ---")
    else:
        print(text)

def handle_list_names(pkg_map):
    """Print just the operator names (naturally sorted, one per line, no header)."""
    names = [pkg for pkg in sorted(pkg_map.keys(), key=natural_sort_key)
             if pkg_map[pkg]["channels"]]
    if not names:
        print("No operators found.")
        return
    print("\n".join(names))

def load_operator_list(list_file):
    """Read operator names from a file, one per line (blank lines/whitespace ignored).

    Returns a list of names in file order (leading/trailing whitespace and any
    trailing '#' comments are stripped).
    """
    names = []
    with open(list_file, 'r') as f:
        for line in f:
            name = line.split('#', 1)[0].strip()
            if name:
                names.append(name)
    return names

def filter_pkg_map(pkg_map, names):
    """Return a pkg_map restricted to the given operator names.

    Only names that exist as packages (with channels) are kept. Returns a new
    dict sharing the same per-package data structures.
    """
    return {name: pkg_map[name] for name in names
            if name in pkg_map and pkg_map[name]["channels"]}

def check_operator_list(pkg_map, names):
    """Return the list of requested names that do not exist as packages."""
    missing = []
    for name in names:
        if name not in pkg_map or not pkg_map[name]["channels"]:
            missing.append(name)
    return missing

# --- Main Entry Point ---

def main():
    usage_examples = """
Examples of usage:
  1. Full automated run for oc-mirror v2 (Red Hat v4.20):
     ./imagesetconfig-generator.py -c registry.redhat.io/redhat/redhat-operator-index:v4.20 --fetch --extract --generate myset --v2

  2. Handle GPG signature failures on RHEL bastion:
     ./imagesetconfig-generator.py -c registry.redhat.io/... --fetch --tls-verify false --disable-signature-policy

  3. Generate from an existing local config folder with verbose logging:
     ./imagesetconfig-generator.py -c my.registry/catalog:v1 --generate output.yaml --configs /tmp/my_configs --v1 --verbose

  4. Extended timeout for slow registry connections:
     ./imagesetconfig-generator.py -c registry.redhat.io/... --fetch --timeout 1800

  5. List operators (name/display name/default channel) like `oc-mirror list operators`:
     ./imagesetconfig-generator.py -c registry.redhat.io/... --extract --oc-mirror-list-operators
    """

    parser = argparse.ArgumentParser(
        description=f'OpenShift ImageSetConfiguration Generator v{VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=usage_examples
    )
    parser.add_argument('-c', '--catalog', required=True, help='Catalog image URL')
    parser.add_argument('--fetch', action='store_true', help='Pull image via podman')
    parser.add_argument('--extract', action='store_true', help='Extract /configs from image')
    parser.add_argument('--configs', help='Optional: Custom folder path for FBC configs')
    parser.add_argument('--generate', help='Output filename (e.g., config.yaml)')
    parser.add_argument('--timeout', type=int, default=600, help='Timeout for podman pull (default: 600s)')
    parser.add_argument('--tls-verify', type=str2bool, default=True, help='Toggle TLS verification (true/false)')
    parser.add_argument('--disable-signature-policy', action='store_true', help='Bypass GPG signature verification (only when you trust the registry and the Red Hat GPG key is missing from the trust store)')
    parser.add_argument('--version-comment', action='store_true', help='Add available versions as a comment below each channel')
    parser.add_argument('--min-max-version', action='store_true', help='Add minVersion/maxVersion keys per channel (can be combined with --version-comment)')
    parser.add_argument('--oc-mirror-list-operators', action='store_true', help='Print a table of NAME/DISPLAY NAME/DEFAULT CHANNEL mirroring `oc-mirror list operators` (requires extracted configs; combine with --extract to pull them)')
    parser.add_argument('--list-operators', action='store_true', help='Print just the operator names, one per line (no header or columns)')
    parser.add_argument('--from-operator-list', help='File of operator names (one per line) to restrict --generate to; unknown operators cause exit unless --continue-on-error is set')
    parser.add_argument('--continue-on-error', action='store_true', help='When used with --from-operator-list, generate the config even if some operators are missing (mirrors oc-mirror v1 --continue-on-error)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging of file processing')
    
    v_group = parser.add_mutually_exclusive_group()
    v_group.add_argument('--v1', action='store_true', help='Generate for oc-mirror v1 (v1alpha2)')
    v_group.add_argument('--v2', action='store_true', help='Generate for oc-mirror v2 (v2alpha1)')
    
    args = parser.parse_args()

    print(f"--- ImageSetConfiguration Generator v{VERSION} ---", file=sys.stderr)
    if args.from_operator_list and not args.generate:
        print("\n[!] --from-operator-list requires --generate.")
        print("    e.g. --from-operator-list operators.txt --generate config.yaml\n")
        sys.exit(1)

    if not (args.fetch or args.extract or args.generate or args.oc_mirror_list_operators or args.list_operators):
        print("\n[!] ACTION REQUIRED: You must specify at least one action.")
        print("    Please use one or more of: --fetch, --extract, --generate, --oc-mirror-list-operators, --list-operators")
        print("    Run with -h for full usage details.\n")
        sys.exit(1)

    config_path = args.configs if args.configs else os.path.join('/tmp', get_safe_dirname(args.catalog))

    output_file = None
    if args.generate:
        output_file = args.generate if args.generate.endswith('.yaml') else args.generate + '.yaml'
        _check_output_writable(output_file)

    if args.fetch:
        handle_fetch(args.catalog, args.tls_verify, args.timeout, args.disable_signature_policy)

    if args.extract:
        handle_extract(args.catalog, config_path, tls_verify=args.tls_verify)

    if args.oc_mirror_list_operators or args.list_operators or args.generate:
        if not os.path.exists(config_path):
            print(f"Error: Directory {config_path} missing. Run with --extract first.")
            sys.exit(1)

        pkg_map = handle_parse_fbc(config_path, verbose=args.verbose)

        if args.oc_mirror_list_operators:
            handle_list_operators(args.catalog, pkg_map)
        elif args.list_operators:
            handle_list_names(pkg_map)

        if args.generate:
            if args.from_operator_list:
                try:
                    names = load_operator_list(args.from_operator_list)
                except OSError as e:
                    print(f"Error: Cannot read operator list {args.from_operator_list}: {e}")
                    sys.exit(1)
                missing = check_operator_list(pkg_map, names)
                if missing:
                    if not args.continue_on_error:
                        print("Error: The following operators were not found in the catalog:")
                        for name in missing:
                            print(f"  {name}")
                        print("Use --continue-on-error to generate a config for the operators that were found.")
                        sys.exit(1)
                    else:
                        print(f"Warning: {len(missing)} operator(s) not found; continuing with those that were found:")
                        for name in missing:
                            print(f"  {name}")
                pkg_map = filter_pkg_map(pkg_map, names)
                if not pkg_map:
                    print("Error: No operators from the list were found in the catalog.")
                    print(f"    Check {args.from_operator_list} contains valid operator names.")
                    sys.exit(1)

            mirror_version = 'v2' if args.v2 else 'v1'
            catalog_digest = resolve_catalog_digest(args.catalog)
            if catalog_digest:
                print(f"--- Pinned digest for {args.catalog}: {catalog_digest} ---", file=sys.stderr)
            else:
                print(f"--- Note: catalog digest unavailable for {args.catalog} "
                      f"(image not present locally); omitting pin comment ---", file=sys.stderr)
            write_image_set_config(output_file, args.catalog, pkg_map, version=mirror_version,
                                   version_comments=args.version_comment,
                                   min_max_version=args.min_max_version,
                                   catalog_digest=catalog_digest)

if __name__ == "__main__":
    main()
