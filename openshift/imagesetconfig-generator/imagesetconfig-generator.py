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
VERSION = "0.14"

# TODO:
# 1. [FIXED] write_image_set_config: the '# default' comment (and _default stripping)
#    relied on substring matching and could match the wrong package/channel (e.g. a
#    package whose name is a prefix of another, like amq-streams vs amq-streams-console).
#    Now uses exact name matching via regex + op_defaults dict. Also fixed YAML-quoted
#    channel names (e.g. '3.15') breaking lookups.
# 2. [DOC] README example output (line ~132) shows '_default: release-2.10  # default',
#    but the code strips '_default:' lines and only appends '  # default' as a comment.
# 3. [REFACTOR] write_image_set_config: pkg_entry['_default'] is stored on every entry
#    regardless of version, then only used for comment annotation. Compute the '# default'
#    marker directly instead.
# 4. [BUG] handle_extract does not pass '--tls-verify' to 'podman create/cp', so the
#    TLS toggle only affects the pull step. Also handle_fetch uses 'podman search' as an
#    extra network call for auth verification.

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

# --- Core Functional Blocks ---

def handle_fetch(catalog, tls_verify, timeout, disable_sig):
    """Checks auth and pulls the catalog image via podman."""
    registry = catalog.split('/')[0]
    print(f"--- Verifying authentication for {registry} ---")
    
    auth_cmd = ['podman', 'search', '--limit', '1', f'--tls-verify={str(tls_verify).lower()}', catalog]
    if subprocess.run(auth_cmd, capture_output=True).returncode != 0:
        print(f"\n[!] ERROR: Authentication failed. Please run: podman login {registry}")
        sys.exit(1)

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
        
        subprocess.run(pull_cmd, check=True)
    finally:
        signal.alarm(0)
        if tmp_policy and os.path.exists(tmp_policy):
            os.remove(tmp_policy)

def handle_extract(catalog, dest_path):
    """Creates temporary container to 'cp' the /configs directory out."""
    container_id = None
    try:
        print(f"--- Extracting /configs to {dest_path} ---")
        container_id = subprocess.run(['podman', 'create', catalog], capture_output=True, text=True, check=True).stdout.strip()
        if os.path.exists(dest_path): shutil.rmtree(dest_path)
        os.makedirs(dest_path)
        subprocess.run(['podman', 'cp', f"{container_id}:/configs/.", dest_path], check=True)
    finally:
        if container_id:
            subprocess.run(['podman', 'rm', '-f', container_id], capture_output=True)

def handle_parse_fbc(config_dir, verbose=False):
    """Walks the config directory and builds a map of packages and channels.

    Returns a dict of pkg -> {"channels": set, "default": str,
    "versions": {channel: [sorted versions]}}. Versions are resolved from the
    'olm.package' property of each bundle (falling back to the bundle name).
    """
    pkg_map = {}
    bundle_versions = {}
    print(f"\n{'STATUS':<12} | {'OPERATOR':<35} | {'CHANNEL/VERSION'}")
    print("-" * 80)
    for root, _, files in os.walk(config_dir):
        for file in files:
            file_path = os.path.join(root, file)
            parser = None
            
            # Identify target files
            is_target = file.endswith(('.json', '.yaml', '.yml'))
            
            if verbose and is_target:
                print(f"Reading {file_path} ...", end='', flush=True)

            # Select parser based on file extension
            if file.endswith('.json'):
                parser = lambda f: extract_json_objects(f.read())
            elif file.endswith(('.yaml', '.yml')):
                parser = lambda f: yaml.safe_load_all(f)
            
            if parser:
                if verbose:
                    print(" OK")
                try:
                    with open(file_path, 'r') as f:
                        for doc in parser(f):
                            if not isinstance(doc, dict): continue
                            if doc.get('schema') == 'olm.package':
                                name = doc.get('name')
                                if name:
                                    if name not in pkg_map: pkg_map[name] = {"channels": set(), "default": None, "versions": {}}
                                    pkg_map[name]["default"] = doc.get('defaultChannel')
                                    if not verbose:
                                        print(f"{'PACKAGE':<12} | {name:<35} | Default: {doc.get('defaultChannel')}")
                            elif doc.get('schema') == 'olm.channel':
                                pkg = doc.get('package')
                                chan = doc.get('name')
                                if pkg and chan:
                                    if pkg not in pkg_map: pkg_map[pkg] = {"channels": set(), "default": None, "versions": {}}
                                    if chan not in pkg_map[pkg]["channels"]:
                                        pkg_map[pkg]["channels"].add(chan)
                                        pkg_map[pkg]["versions"][chan] = []
                                        if not verbose:
                                            print(f"{'CHANNEL':<12} | {pkg:<35} | -> {chan}")
                                    for entry in (doc.get('entries') or []):
                                        ename = entry.get('name')
                                        if ename and ename not in pkg_map[pkg]["versions"][chan]:
                                            pkg_map[pkg]["versions"][chan].append(ename)
                            elif doc.get('schema') == 'olm.bundle':
                                name = doc.get('name')
                                if name:
                                    for prop in (doc.get('properties') or []):
                                        if prop.get('type') == 'olm.package':
                                            bundle_versions[name] = prop.get('value', {}).get('version')
                                            break
                except Exception as e:
                    if verbose: print(f" FAIL ({e})")
                    else: print(f"Warning: Could not parse {file}: {e}")
            elif verbose and is_target:
                # Should not happen given is_target logic, but good for safety
                print(" SKIP (No Parser)")

    # Resolve channel entry names to versions, sorted naturally
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

    return pkg_map

def write_image_set_config(output_file, catalog, pkg_map, version='v1', version_comments=False, min_max_version=False):
    """Generates the YAML file with version-specific validation and formatting.

    If version_comments is True, a '# versions: ...' comment is emitted below
    each channel listing the available versions.
    If min_max_version is True, each channel gets 'minVersion'/'maxVersion' keys
    (first/last of the channel's sorted versions) instead of the comment.
    """
    op_list = []
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
        pkg_entry["_default"] = actual_default
        op_list.append(pkg_entry)

    api_version = "mirror.openshift.io/v2alpha1" if version == 'v2' else "mirror.openshift.io/v1alpha2"
    config = {"apiVersion": api_version, "kind": "ImageSetConfiguration", "mirror": {"operators": [{"catalog": catalog, "packages": op_list}]}}
    raw_yaml = yaml.dump(config, default_flow_style=False, sort_keys=False)

    final_lines = []
    op_defaults = {p['name']: p['_default'] for p in op_list}
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
        if "_default:" not in line: final_lines.append(line)
        if version_comments and current_pkg and chan_line:
            versions = pkg_map[current_pkg].get("versions", {}).get(chan)
            if versions:
                final_lines.append(f"      # versions: {', '.join(versions)}")

    with open(output_file, 'w') as f: f.write("\n".join(final_lines))
    print(f"\n--- SUCCESS: Generated {output_file} (Format: {version}) ---")

# --- Main Entry Point ---

def main():
    usage_examples = """
Examples of usage:
  1. Full automated run for oc-mirror v2 (Red Hat v4.16):
     ./imagesetconfig-generator.py -c registry.redhat.io/redhat/redhat-operator-index:v4.16 --fetch --extract --generate myset --v2

  2. Handle GPG signature failures on RHEL bastion:
     ./imagesetconfig-generator.py -c registry.redhat.io/... --fetch --tls-verify false --disable-signature-policy

  3. Generate from an existing local config folder with verbose logging:
     ./imagesetconfig-generator.py -c my.registry/catalog:v1 --generate output.yaml --configs /tmp/my_configs --v1 --verbose

  4. Extended timeout for slow registry connections:
     ./imagesetconfig-generator.py -c registry.redhat.io/... --fetch --timeout 1800
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
    parser.add_argument('--disable-signature-policy', action='store_true', help='Bypass GPG signature checks')
    parser.add_argument('--version-comment', action='store_true', help='Add available versions as a comment below each channel')
    parser.add_argument('--min-max-version', action='store_true', help='Add minVersion/maxVersion keys per channel (can be combined with --version-comment)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging of file processing')
    
    v_group = parser.add_mutually_exclusive_group()
    v_group.add_argument('--v1', action='store_true', help='Generate for oc-mirror v1 (v1alpha2)')
    v_group.add_argument('--v2', action='store_true', help='Generate for oc-mirror v2 (v2alpha1)')
    
    args = parser.parse_args()

    print(f"--- ImageSetConfiguration Generator v{VERSION} ---")
    if not (args.fetch or args.extract or args.generate):
        print("\n[!] ACTION REQUIRED: You must specify at least one action.")
        print("    Please use one or more of: --fetch, --extract, --generate")
        print("    Run with -h for full usage details.\n")
        sys.exit(1)

    config_path = args.configs if args.configs else os.path.join('/tmp', get_safe_dirname(args.catalog))

    if args.fetch:
        handle_fetch(args.catalog, args.tls_verify, args.timeout, args.disable_signature_policy)

    if args.extract:
        handle_extract(args.catalog, config_path)

    if args.generate:
        if not os.path.exists(config_path):
            print(f"Error: Directory {config_path} missing. Run with --extract first.")
            sys.exit(1)
        
        mirror_version = 'v2' if args.v2 else 'v1'
        pkg_map = handle_parse_fbc(config_path, verbose=args.verbose)
        write_image_set_config(args.generate if args.generate.endswith('.yaml') else args.generate + '.yaml', 
                               args.catalog, pkg_map, version=mirror_version,
                               version_comments=args.version_comment,
                               min_max_version=args.min_max_version)

if __name__ == "__main__":
    main()
