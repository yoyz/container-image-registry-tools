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
VERSION = "0.1"

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

def handle_parse_fbc(config_dir):
    """Walks the config directory and builds a map of packages and channels."""
    pkg_map = {}
    print(f"\n{'STATUS':<12} | {'OPERATOR':<35} | {'CHANNEL/VERSION'}")
    print("-" * 80)
    for root, _, files in os.walk(config_dir):
        for file in files:
            if file.endswith(('.json', '.yaml', '.yml')):
                with open(os.path.join(root, file), 'r') as f:
                    for doc in extract_json_objects(f.read()):
                        if not isinstance(doc, dict): continue
                        if doc.get('schema') == 'olm.package':
                            name = doc.get('name')
                            if name:
                                if name not in pkg_map: pkg_map[name] = {"channels": set(), "default": None}
                                pkg_map[name]["default"] = doc.get('defaultChannel')
                                print(f"{'PACKAGE':<12} | {name:<35} | Default: {doc.get('defaultChannel')}")
                        elif doc.get('schema') == 'olm.channel':
                            pkg = doc.get('package')
                            chan = doc.get('name')
                            if pkg and chan:
                                if pkg not in pkg_map: pkg_map[pkg] = {"channels": set(), "default": None}
                                if chan not in pkg_map[pkg]["channels"]:
                                    pkg_map[pkg]["channels"].add(chan)
                                    print(f"{'CHANNEL':<12} | {pkg:<35} | -> {chan}")
    return pkg_map

def write_image_set_config(output_file, catalog, pkg_map, version='v1'):
    """Generates the YAML file with version-specific validation and formatting."""
    op_list = []
    for pkg in sorted(pkg_map.keys()):
        data = pkg_map[pkg]
        sorted_chans = sorted(list(data["channels"]), key=natural_sort_key)
        if not sorted_chans: continue

        # Ensure defaultChannel is present in the channel list for v2 compliance
        actual_default = data["default"]
        if actual_default not in sorted_chans:
            actual_default = sorted_chans[-1]

        pkg_entry = {"name": pkg, "channels": [{"name": c} for c in sorted_chans]}
        if version == 'v2': pkg_entry["defaultChannel"] = actual_default
        pkg_entry["_default"] = actual_default
        op_list.append(pkg_entry)

    api_version = "mirror.openshift.io/v2alpha1" if version == 'v2' else "mirror.openshift.io/v1alpha2"
    config = {"apiVersion": api_version, "kind": "ImageSetConfiguration", "mirror": {"operators": [{"catalog": catalog, "packages": op_list}]}}
    raw_yaml = yaml.dump(config, default_flow_style=False, sort_keys=False)
    
    final_lines = []
    current_default = None
    for line in raw_yaml.splitlines():
        if "- name:" in line and "channels:" not in line:
            pkg_match = [p for p in op_list if f"name: {p['name']}" in line]
            if pkg_match: current_default = pkg_match[0]['_default']
        if current_default and f"name: {current_default}" in line and "defaultChannel:" not in line: line += "  # default"
        if "_default:" not in line: final_lines.append(line)

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

  3. Generate from an existing local config folder:
     ./imagesetconfig-generator.py -c my.registry/catalog:v1 --generate output.yaml --configs /tmp/my_configs --v1

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
    
    v_group = parser.add_mutually_exclusive_group()
    v_group.add_argument('--v1', action='store_true', help='Generate for oc-mirror v1 (v1alpha2)')
    v_group.add_argument('--v2', action='store_true', help='Generate for oc-mirror v2 (v2alpha1)')
    
    args = parser.parse_args()

    print(f"--- ImageSetConfiguration Generator v{VERSION} ---")

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
        pkg_map = handle_parse_fbc(config_path)
        write_image_set_config(args.generate if args.generate.endswith('.yaml') else args.generate + '.yaml', 
                               args.catalog, pkg_map, version=mirror_version)

if __name__ == "__main__":
    main()
