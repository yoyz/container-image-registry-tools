#!/usr/bin/env python3
# vim: set tabstop=4 shiftwidth=4 expandtab:
# ==============================================================================
# quayoperatorbundletoversion.py
# ------------------------------------------------------------------------------
# Lists the operator versions available in a Quay/Docker registry:
#   1. Discover repositories through the registry API (Quay API v1 / Registry V2
#      catalog), reusing the approach of quayspaceconsumption.py.
#   2. Keep only the operator bundle images (default filter: name ends with "-bundle").
#   3. `skopeo list-tags` on each bundle image.
#   4. Skip the signature tags (ending in ".sig").
#   5. `skopeo inspect` each remaining tag to fetch the operator bundle manifest.
#   6. Parse the manifest labels to list the available versions per operator.
#
# The version is read from the image label "version" (e.g. "4.11.0"), and the
# operator identity from "operators.operatorframework.io.bundle.package.v1".
#
# This tool only does GET/HEAD actions (requests) and read-only podman/skopeo
# commands, it never modifies the registry.
# ==============================================================================

from urllib.parse import urlparse
import requests, json, getopt, sys, re, os, signal, base64, csv, subprocess
import urllib3

# Suppress SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global Session for connection pooling
SESSION = requests.Session()

# Global Configuration
CONFIG = {
    "URL": "",
    "HOST": "",
    "PREFIX": "",
    "TOKEN": "",
    "USER": "",
    "PASS": "",
    "REPOS": [],
    "REPO_FILE": "",
    "OUTPUT_CSV": "",
    "DEBUG": False,
    "NO_VERIFY": False,
    "AUTHFILE": "",
    "FILTER": r"-bundle$",
    "TIMEOUT": 300,
    "OC_MIRROR_V2": "",
    "CATALOG": "registry.redhat.io/redhat/redhat-operator-index:v4.20",
    "TARGET_CATALOG": "openshift-marketplace/redhat-operators-disconnected",
    "ARCHS": ["amd64"],
    "OCP_CHANNELS": [],
    "FULL_CHANNELS": False,
    "CATALOG_PATTERNS": ["redhat-operator", "certified-operator", "community-operators", "redhat-marketplace"],
    "CATALOG_CANDIDATES": [],
    "CATALOG_EXPLICIT": False
}

# Bundle label constants
LBL_VERSION = "version"
LBL_PACKAGE = "operators.operatorframework.io.bundle.package.v1"
LBL_CHANNELS = "operators.operatorframework.io.bundle.channels.v1"
LBL_DEFAULT_CHANNEL = "operators.operatorframework.io.bundle.channel.default.v1"
LBL_OCP_VERSIONS = "com.redhat.openshift.versions"

# --- SIGNAL HANDLING (Ctrl+C) ---
def signal_handler(sig, frame):
    print("\n\n[!] Interrupt received (Ctrl+C). Forcing Exit...")
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

def debug(msg):
    if CONFIG["DEBUG"]: print(msg)

def print_usage():
    script_name = os.path.basename(sys.argv[0])
    print(f"""
{script_name}
============================
Lists the operator versions available in a Quay/Docker registry:
  1. discover repositories via the registry API
     (Quay API v1 with a token, or Registry V2 catalog with user/pass)
  2. filter images ending in "-bundle"
  3. skopeo list-tags <repo>        -> list image tags
  4. skopeo inspect <repo>:<tag>    -> read the operator bundle manifest
  5. parse manifest labels          -> extract version / package / channels

Usage:
  python3 {script_name} -u <URL> [OPTIONS]

Options:
  -u <URL>        Registry URL (required unless -r/-f is used),
                  e.g. https://quay.example.com or quay420...:8443
  -t <TOKEN>      OAuth Token (Quay API v1 discovery)
  -U <USER>       Username (Registry V2 catalog discovery)
  -P <PASS>       Password (Registry V2 catalog discovery)
  -r <REPO>       Process a specific repository directly (skips discovery).
                  Can be used multiple times.
  -f <FILE>       File containing the list of repositories to process
                  (one per line).
  -o <FILE>       Export results to a CSV file
  --oc-mirror-v2 <FILE> Generate an oc-mirror ImageSetConfiguration YAML from
                  the discovered operator packages/channels. Use "-" for stdout.
  --catalog <IMAGE> Catalog image used in the generated imagesetconfig
                  (default: registry.redhat.io/redhat/redhat-operator-index:v4.20)
  --target-catalog <IMAGE> targetCatalog used in the generated imagesetconfig
                  (default: openshift-marketplace/redhat-operators-disconnected)
  --arch <ARCH>   Architecture for the imagesetconfig platform section
                  (default: amd64, repeatable)
  --ocp-channel <SPEC> Add an OpenShift platform release channel to the
                  imagesetconfig platform section (repeatable).
                  Format: <name>[:<min>[:<max>]], e.g. "stable-4.20:4.20.10:4.20.11".
                  This mirrors the OCP platform release and is NOT derived from
                  operator bundles; if omitted, no platform channels are emitted.
  --full-channels Add `full: true` to the platform channels, letting oc-mirror
                  set minVersion/maxVersion to the first/last release in the channel.
  --filter <REGEX> Bundle name filter applied on discovered repositories
                  (default: "-bundle$")
  --no-verify     Add --tls-verify=false to skopeo commands
  --authfile <FILE> Path to the auth file passed to skopeo.
                  If not provided, ~/.docker/config.json is used when present.
  -d              Enable debug output
  -h, --help      Show this help message and exit

Authentication Modes (same as quayspaceconsumption.py):
  1. Token Mode (-t): Uses Quay API v1.
  2. Credentials (-U/-P): Uses Registry V2 catalog with fallback to
     the Quay search API.
  3. Auto-Auth: If no auth flags are provided, credentials are read from
     ~/.docker/config.json or standard locations.

Examples:
  # 1. Discover all *bundle images on the registry and list their versions
  python3 {script_name} -u quay420.tnc.bootcamp420.lab:8443/

  # 2. Only look under a sub-path of the registry
  python3 {script_name} -u quay420.tnc.bootcamp420.lab:8443/ocp/420

  # 3. Process a single known bundle repository
  python3 {script_name} -r quay420.tnc.bootcamp420.lab:8443/ocp/420/quay/quay-operator-bundle

  # 4. Process repos from a file and export to CSV
  python3 {script_name} -f repos.txt -o report.csv

  # 5. Keep every image containing "bundle" in its name (not only "-bundle$")
  python3 {script_name} -u quay420.tnc.bootcamp420.lab:8443/ --filter 'bundle'

  # 6. Generate an oc-mirror imagesetconfig from the discovered operators
  python3 {script_name} -u quay420.tnc.bootcamp420.lab:8443/ocp/420 --oc-mirror-v2 imagesetconfig.yaml
""")
    sys.exit(0)

def run_cmd(args, label):
    """Run a command, return its stdout (stripped) or None on failure."""
    if CONFIG["DEBUG"]:
        print(f"[CMD {label}] {' '.join(args)}")
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=CONFIG["TIMEOUT"]
        )
        if proc.returncode != 0:
            err = (proc.stderr or "").strip()
            print(f"[WARN] {label} failed for: {' '.join(args)}\n  {err}")
            return None
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[ERROR] {label} timed out after {CONFIG['TIMEOUT']}s")
        return None
    except Exception as e:
        print(f"[ERROR] {label} failed: {e}")
        return None

def auth_args():
    """Common auth/TLS flags placed AFTER the skopeo subcommand."""
    args = []
    if CONFIG["NO_VERIFY"]:
        args.append("--tls-verify=false")
    if CONFIG["AUTHFILE"]:
        args.extend(["--authfile", CONFIG["AUTHFILE"]])
    return args

def detect_authfile():
    """Auto-select ~/.docker/config.json as the auth file when present."""
    if CONFIG["AUTHFILE"]:
        return
    for path in ("~/.docker/config.json",):
        expanded = os.path.expanduser(path)
        if os.path.exists(expanded):
            CONFIG["AUTHFILE"] = expanded
            print(f"[INFO] Auto-detected auth file: {expanded}")
            return

# --- AUTH / DISCOVERY (ported from quayspaceconsumption.py) ---

def get_registry_auth(file_path, registry_host):
    """
    Extracts credentials from ~/.docker/config.json or compatible files.
    Returns: {'username': '...', 'password': '...'} or {} if not found.
    """
    file_path = os.path.expanduser(file_path)
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, 'r') as f:
            config_json = json.load(f)

        auths = config_json.get("auths", {})

        keys_to_try = [
            registry_host,
            f"https://{registry_host}",
            f"http://{registry_host}",
            registry_host.replace("https://", "").replace("http://", "")
        ]

        reg_data = None
        for k in keys_to_try:
            if k in auths:
                reg_data = auths[k]
                break

        if not reg_data:
            return {}

        if "auth" in reg_data:
            try:
                decoded_auth = base64.b64decode(reg_data["auth"]).decode('utf-8')
                if ":" in decoded_auth:
                    username, password = decoded_auth.split(":", 1)
                    return {"username": username, "password": password}
            except Exception as e: debug(f"[DEBUG] Suppressed Exception: {e}")

        if "username" in reg_data and "password" in reg_data:
            return {
                "username": reg_data["username"],
                "password": reg_data["password"]
            }

    except Exception:
        pass

    return {}

def get_service_name(base_url):
    try:
        resp = SESSION.get(f"{base_url}/v2/", verify=False, timeout=10)
        auth_header = resp.headers.get("Www-Authenticate", "")
        m = re.search(r'service="([^"]+)"', auth_header)
        if m: return m.group(1)
        return base_url.replace("https://", "").replace("http://", "").split("/")[0]
    except Exception:
        return base_url.replace("https://", "").replace("http://", "").split("/")[0]

def discover_api_v1_repos(base_url, token):
    """Discover repositories through the Quay API v1 (token mode)."""
    debug("[INFO] Discovering repositories via API v1...")
    discovered_repos = []
    try:
        resp = SESSION.get(f"{base_url}/api/v1/user/",
                           headers={"Authorization": f"Bearer {token}"}, verify=False)
        data = resp.json()
        orgs = [o['name'] for o in data.get('organizations', [])]
        if 'username' in data: orgs.append(data['username'])

        for org in orgs:
            page = 1
            while True:
                r_resp = SESSION.get(f"{base_url}/api/v1/repository",
                                     params={'namespace': org, 'limit': 100, 'page': page},
                                     headers={"Authorization": f"Bearer {token}"}, verify=False)
                if r_resp.status_code != 200:
                    break
                r_data = r_resp.json()
                repos = r_data.get('repositories', [])
                for r in repos:
                    discovered_repos.append(f"{org}/{r['name']}")
                debug(f"[INFO] Found {len(repos)} repos in namespace '{org}' (page {page})")
                has_additional = r_data.get('has_additional', False)
                if not has_additional:
                    break
                page += 1
    except Exception as e:
        print(f"[ERROR] API v1 Discovery failed: {e}")
        sys.exit(1)

    discovered_repos.sort()
    return discovered_repos

def discover_v2_catalog(base_url, user, password, service_name):
    """Discover repositories via the Registry V2 catalog, with a Quay search fallback."""
    debug(f"[INFO] Starting V2 Discovery (Service: {service_name})...")
    discovered_repos = []

    cat_token = ""
    try:
        params = {'service': service_name}
        auth_resp = SESSION.get(f"{base_url}/v2/auth", auth=(user, password), params=params, verify=False)
        if auth_resp.status_code == 200:
            cat_token = auth_resp.json().get('token') or auth_resp.json().get('access_token')
    except Exception as e: debug(f"[DEBUG] Suppressed Exception: {e}")

    if cat_token:
        next_url = f"{base_url}/v2/_catalog?n=1000"
        while next_url:
            try:
                cat_resp = SESSION.get(next_url, headers={"Authorization": f"Bearer {cat_token}"}, verify=False)
                if cat_resp.status_code == 200:
                    page_repos = cat_resp.json().get("repositories", [])
                    discovered_repos.extend(page_repos)
                    debug(f"[INFO] Fetched {len(page_repos)} repos.")

                    link_header = cat_resp.headers.get("Link")
                    next_url = None
                    if link_header:
                        match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
                        if match:
                            next_link = match.group(1)
                            next_url = next_link if next_link.startswith("http") else (f"{base_url}{next_link}" if next_link.startswith("/") else f"{base_url}/v2/{next_link}")
                else:
                    debug(f"[INFO] Catalog returned {cat_resp.status_code}; falling back to search API")
                    next_url = None
            except Exception:
                next_url = None

    if not discovered_repos:
        debug("[INFO] Catalog empty/blocked. Using Search fallback...")
        try:
            page = 1
            while True:
                params = {'query': '', 'page': page}
                resp = SESSION.get(f"{base_url}/api/v1/find/repositories",
                                   auth=(user, password), params=params, verify=False)
                if resp.status_code != 200:
                    debug(f"[INFO] Search API returned {resp.status_code}")
                    break
                data = resp.json()
                results = data.get('results', []) or []
                for r in results:
                    name = r.get('full_name') or f"{r.get('namespace', {}).get('name')}/{r.get('name')}"
                    if name and '/' in name:
                        discovered_repos.append(name)
                debug(f"[INFO] Search API page {page}: {len(results)} results")
                next_page = data.get('next_page')
                if not next_page or next_page == page:
                    break
                page = next_page
        except Exception as e: debug(f"[DEBUG] Suppressed Exception: {e}")

    discovered_repos.sort()
    return discovered_repos

def filter_bundle_repos(repos):
    """Keep only repositories matching the configured bundle name filter."""
    rx = re.compile(CONFIG["FILTER"])
    keep = [r for r in repos if rx.search(r)]
    if CONFIG["DEBUG"]:
        for r in sorted(set(repos) - set(keep)):
            debug(f"[INFO]  - skipped (no bundle match): {r}")
    return keep

# --- STEP 3/4: skopeo list-tags (skipping .sig tags) ---

def is_sig_tag(tag):
    return tag.endswith(".sig")

def skopeo_list_tags(repo):
    """Return the list of tags for a repository, excluding signature tags."""
    args = ["skopeo", "list-tags"] + auth_args() + [f"docker://{repo}"]
    out = run_cmd(args, "LIST-TAGS")
    if out is None:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON from skopeo list-tags for {repo}")
        return []
    tags = data.get("Tags") or data.get("RepoTags") or []
    sig_tags = [t for t in tags if is_sig_tag(t)]
    normal_tags = [t for t in tags if not is_sig_tag(t)]
    if CONFIG["DEBUG"] and sig_tags:
        debug(f"[INFO]  -> skipped {len(sig_tags)} signature tag(s): {', '.join(sig_tags)}")
    return normal_tags

# --- STEP 4/5: skopeo inspect + parse manifest ---

def skopeo_inspect(repo, tag):
    """Run `skopeo inspect` on repo:tag and return the parsed JSON."""
    args = ["skopeo", "inspect"] + auth_args() + [f"docker://{repo}:{tag}"]
    out = run_cmd(args, "INSPECT")
    if out is None:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON from skopeo inspect for {repo}:{tag}")
        return None

def extract_bundle_info(manifest, repo, tag):
    """Pull the relevant fields out of a bundle manifest (skopeo inspect output)."""
    labels = manifest.get("Labels") or {}
    version = labels.get(LBL_VERSION)
    if not version:
        return None
    return {
        "repository": repo,
        "tag": tag,
        "digest": manifest.get("Digest", ""),
        "version": version,
        "package": labels.get(LBL_PACKAGE, ""),
        "channels": labels.get(LBL_CHANNELS, ""),
        "default_channel": labels.get(LBL_DEFAULT_CHANNEL, ""),
        "created": manifest.get("Created", ""),
        "architecture": manifest.get("Architecture", ""),
        "os": manifest.get("Os", ""),
        "ocp_versions": labels.get(LBL_OCP_VERSIONS, "")
    }

def natural_key(value):
    """Sort key for human-friendly version ordering (e.g. 4.10.0 < 4.11.0)."""
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", value)]

def parse_ocp_versions(label):
    """Extract OCP minor versions from a com.redhat.openshift.versions label.

    e.g. '=v4.20'           -> ['4.20']
         'v4.20-v4.21'      -> ['4.20', '4.21']
         'v4.18-v4.19-v4.20-v4.21' -> ['4.18', '4.19', '4.20', '4.21']
    Returns an empty list if the label is absent/unparseable.
    """
    if not label:
        return []
    return sorted(set(re.findall(r"v(\d+\.\d+)", label)), key=natural_key)

def strip_host(repo):
    """Return the repository path without the registry host prefix."""
    host = CONFIG["HOST"]
    if host and repo.startswith(host + "/"):
        return repo[len(host) + 1:]
    return repo

def pick_catalog_tag(tags, ocp_minors):
    """Pick the catalog tag matching the discovered OCP versions, else the first."""
    if not tags:
        return ""
    for tag in tags:
        if any(minor in tag for minor in ocp_minors):
            return tag
    return tags[0]

def detect_catalogs(repos):
    """Find operator catalog repositories by name pattern (list-tags only).

    No /configs deep-dive is done: catalogs are guessed from the repo name
    (redhat-operator / certified-operator / community-operators /
    redhat-marketplace). Returns a list of {repo, tags} ordered with
    "redhat-operator" first.
    """
    matched = {}
    for pat in CONFIG["CATALOG_PATTERNS"]:
        for r in repos:
            if pat in r:
                matched.setdefault(r, pat)
    ordered = sorted(
        matched,
        key=lambda r: (CONFIG["CATALOG_PATTERNS"].index(matched[r]), r)
    )
    candidates = []
    for repo in ordered:
        tags = skopeo_list_tags(repo)
        candidates.append({"repo": repo, "tags": tags})
        if CONFIG["DEBUG"]:
            debug(f"[INFO]  catalog candidate: {repo} tags={tags}")
    return candidates

def process_repo(repo):
    """List tags, inspect each one, and return a list of bundle info dicts."""
    print(f"Processing: {repo}")
    tags = skopeo_list_tags(repo)
    if not tags:
        print("  >> No tags found (or all were signature tags).")
        return []

    results = []
    seen_digests = set()
    for tag in tags:
        manifest = skopeo_inspect(repo, tag)
        if not manifest:
            continue
        info = extract_bundle_info(manifest, repo, tag)
        if not info:
            if CONFIG["DEBUG"]:
                debug(f"[INFO]  -> {tag}: no operator bundle labels/version, skipped")
            continue
        # Avoid re-inspecting the same digest when several tags point to it.
        if info["digest"] in seen_digests:
            continue
        seen_digests.add(info["digest"])
        results.append(info)
    return results

# --- REPORTING ---

def print_report(results):
    print("\nOPERATOR BUNDLE VERSIONS")
    print("=" * 72)

    by_repo = {}
    for info in results:
        by_repo.setdefault(info["repository"], []).append(info)

    total_versions = 0
    for repo in sorted(by_repo):
        infos = by_repo[repo]
        versions = sorted({i["version"] for i in infos}, key=natural_key)
        package = infos[0]["package"] or "(unknown)"
        channels = infos[0]["channels"] or "(none)"
        default_channel = infos[0]["default_channel"] or "(none)"
        total_versions += len(versions)

        print(f"\n  {repo}")
        print(f"    {'Package':.<20} {package}")
        print(f"    {'Channels':.<20} {channels}")
        print(f"    {'Default ch.':.<20} {default_channel}")
        ocp_versions = sorted({f"v{v}" for i in infos for v in parse_ocp_versions(i.get("ocp_versions"))}, key=natural_key)
        if ocp_versions:
            print(f"    {'Supported OCP':.<20} {', '.join(ocp_versions)}")
        print(f"    {'Versions':.<20} {len(versions)} available")
        for v in versions:
            print(f"      - {v}")

    print("\n" + "-" * 72)
    print(f"TOTAL: {len(by_repo)} operator bundle(s), {total_versions} distinct version(s)")

def yaml_scalar(value):
    """Return a YAML scalar, quoted when ambiguous (numeric-like or special chars)."""
    s = str(value)
    if s == "":
        return '""'
    if re.search(r": |[#\[\]{},&*!|>'\"%@`\n]", s) or s.strip() != s or re.match(r"^[-?] ", s):
        return '"' + s.replace('"', '\\"') + '"'
    if re.match(r"^-?[0-9]", s):
        return '"' + s + '"'
    return s

def build_oc_mirror_yaml(results):
    """Build an oc-mirror ImageSetConfiguration YAML from the discovered bundles.

    Packages are aggregated/deduped by their package label. Channels and the
    default channel are merged across all bundles belonging to that package.

    platform.channels mirror the OpenShift platform release the user targets;
    they are NOT derived from operator bundles (an operator's OCP-compatibility
    label does not equal the platform release to mirror). They are only emitted
    when --ocp-channel is given.
    """
    # Platform release channels come only from explicit --ocp-channel specs.
    platform_channels = []
    for spec in CONFIG["OCP_CHANNELS"]:
        parts = [p.strip() for p in spec.split(":")]
        ch = {"name": parts[0]}
        if len(parts) > 1 and parts[1]:
            ch["min"] = parts[1]
        if len(parts) > 2 and parts[2]:
            ch["max"] = parts[2]
        platform_channels.append(ch)

    packages = {}
    ocp_minors = set()
    for info in results:
        pkg = (info.get("package") or "").strip()
        if not pkg:
            continue
        entry = packages.setdefault(pkg, {"channels": set(), "default": ""})
        if info.get("default_channel"):
            entry["default"] = entry["default"] or info["default_channel"]
        for ch in (info.get("channels") or "").split(","):
            ch = ch.strip()
            if ch:
                entry["channels"].add(ch)
        for minor in parse_ocp_versions(info.get("ocp_versions")):
            ocp_minors.add(minor)

    # Source catalog: explicit --catalog wins, otherwise a name-based guess
    # from the catalogs detected in the registry (no /configs deep-dive).
    candidates = CONFIG["CATALOG_CANDIDATES"]
    if CONFIG["CATALOG_EXPLICIT"] or not candidates:
        catalog_ref = CONFIG["CATALOG"]
        target_catalog = CONFIG["TARGET_CATALOG"]
        guess_note = False
    else:
        first = candidates[0]
        tag = pick_catalog_tag(first["tags"], ocp_minors)
        catalog_ref = f"{first['repo']}:{tag}" if tag else first["repo"]
        target_catalog = strip_host(first["repo"])
        guess_note = True

    lines = []
    lines.append("kind: ImageSetConfiguration")
    lines.append("apiVersion: mirror.openshift.io/v2alpha1")
    lines.append("mirror:")
    if platform_channels:
        lines.append("  platform:")
        lines.append("    architectures:")
        for arch in CONFIG["ARCHS"]:
            lines.append(f'      - "{arch}"')
        lines.append("    channels:")
        for ch in platform_channels:
            lines.append(f"    - name: {yaml_scalar(ch['name'])}")
            if "min" in ch:
                lines.append(f"      minVersion: {yaml_scalar(ch['min'])}")
            if "max" in ch:
                lines.append(f"      maxVersion: {yaml_scalar(ch['max'])}")
            if CONFIG["FULL_CHANNELS"] and "min" not in ch and "max" not in ch:
                lines.append("      full: true")
        lines.append("    graph: true")
    lines.append("  operators:")
    if guess_note:
        lines.append("  # Source catalog is a name-based guess; no catalog /configs deep-dive discovery is implemented in this tool.")
    lines.append(f"  - catalog: {yaml_scalar(catalog_ref)}")
    lines.append(f"    targetCatalog: {yaml_scalar(target_catalog)}")
    lines.append("    packages:")
    for pkg in sorted(packages):
        data = packages[pkg]
        lines.append(f"    - name: {yaml_scalar(pkg)}")
        if data["default"]:
            lines.append(f"      defaultChannel: {yaml_scalar(data['default'])}")
        lines.append("      channels:")
        for ch in sorted(data["channels"]):
            lines.append(f"      - name: {yaml_scalar(ch)}")
    for extra in candidates[1:]:
        etag = pick_catalog_tag(extra["tags"], ocp_minors)
        eref = f"{extra['repo']}:{etag}" if etag else extra["repo"]
        lines.append("  # Other detected catalog (name-based guess; no /configs deep-dive discovery is implemented in this tool):")
        lines.append(f"  # - catalog: {yaml_scalar(eref)}")
        lines.append(f"  #   targetCatalog: {yaml_scalar(strip_host(extra['repo']))}")
    return "\n".join(lines) + "\n"

def export_oc_mirror_yaml(results, path):
    try:
        text = build_oc_mirror_yaml(results)
        if path == "-":
            print(text)
            return True
        with open(path, 'w') as f:
            f.write(text)
        print(f"\n[INFO] oc-mirror imagesetconfig saved to {path}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to write oc-mirror imagesetconfig: {e}")
        return False

def export_csv(results, path):
    try:
        with open(path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "Repository", "Package", "Channels", "DefaultChannel",
                "Version", "Tag", "Digest", "Created", "Architecture", "OS"
            ])
            for info in sorted(results, key=lambda x: (x["repository"], natural_key(x["version"]))):
                writer.writerow([
                    info["repository"],
                    info["package"],
                    info["channels"],
                    info["default_channel"],
                    info["version"],
                    info["tag"],
                    info["digest"],
                    info["created"],
                    info["architecture"],
                    info["os"]
                ])
        print(f"\n[INFO] Report saved to {path}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to write CSV: {e}")
        return False

# --- MAIN ENTRY ---
def main():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "u:t:U:P:r:f:o:dh",
            ["oc-mirror-v2=", "catalog=", "target-catalog=", "arch=",
             "ocp-channel=", "full-channels",
             "filter=", "no-verify", "authfile=", "help"]
        )
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    for o, a in opts:
        if o == "-u": CONFIG["URL"] = a
        elif o == "-t": CONFIG["TOKEN"] = a
        elif o == "-U": CONFIG["USER"] = a
        elif o == "-P": CONFIG["PASS"] = a
        elif o == "-r": CONFIG["REPOS"].append(a)
        elif o == "-f": CONFIG["REPO_FILE"] = a
        elif o == "-o": CONFIG["OUTPUT_CSV"] = a
        elif o == "-d": CONFIG["DEBUG"] = True
        elif o == "--oc-mirror-v2": CONFIG["OC_MIRROR_V2"] = a
        elif o == "--catalog":
            CONFIG["CATALOG"] = a
            CONFIG["CATALOG_EXPLICIT"] = True
        elif o == "--target-catalog": CONFIG["TARGET_CATALOG"] = a
        elif o == "--arch": CONFIG["ARCHS"].append(a)
        elif o == "--ocp-channel": CONFIG["OCP_CHANNELS"].append(a)
        elif o == "--full-channels": CONFIG["FULL_CHANNELS"] = True
        elif o == "--filter": CONFIG["FILTER"] = a
        elif o == "--no-verify": CONFIG["NO_VERIFY"] = True
        elif o == "--authfile": CONFIG["AUTHFILE"] = a
        elif o == "-h" or o == "--help": print_usage()

    if not CONFIG["URL"] and not CONFIG["REPOS"] and not CONFIG["REPO_FILE"]:
        print("Error: one of -u <URL>, -r <REPO> or -f <FILE> is required")
        print(f"Try 'python3 {os.path.basename(sys.argv[0])} --help' for more information.")
        sys.exit(1)

    # Normalize the base URL (registry scheme + host), keep the path as a prefix
    raw_url = CONFIG["URL"]
    if raw_url:
        if not raw_url.startswith("http"):
            raw_url = "https://" + raw_url
        parsed = urlparse(raw_url)
        CONFIG["URL"] = f"{parsed.scheme}://{parsed.netloc}"
        CONFIG["HOST"] = parsed.netloc
        CONFIG["PREFIX"] = parsed.path.strip('/')

    detect_authfile()

    # --- AUTO-AUTH LOGIC (same as quayspaceconsumption.py) ---
    if not CONFIG["TOKEN"] and (not CONFIG["USER"] or not CONFIG["PASS"]):
        clean_host = CONFIG["HOST"] or CONFIG["URL"].replace("https://", "").replace("http://", "")
        search_paths = [
            "~/.docker/config.json",
            "/run/user/1000/containers/auth.json",
            "/var/lib/kubelet/config.json",
            "./config.json"
        ]
        for path in search_paths:
            creds = get_registry_auth(path, clean_host)
            if creds:
                print(f"[INFO] Auto-detected credentials in {path}")
                CONFIG["USER"] = creds["username"]
                CONFIG["PASS"] = creds["password"]
                break

    # 1. RESOLVE THE LIST OF REPOSITORIES
    repos_to_process = list(CONFIG["REPOS"])

    if CONFIG["REPO_FILE"]:
        try:
            with open(CONFIG["REPO_FILE"], 'r') as f:
                repos_to_process.extend(
                    line.strip().lstrip('/') for line in f
                    if line.strip() and not line.startswith('#')
                )
            debug(f"[INFO] Loaded repositories from {CONFIG['REPO_FILE']}")
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

    if CONFIG["URL"]:
        # 2. DISCOVER REPOSITORIES (API v1 token / V2 catalog, like quayspaceconsumption)
        if CONFIG["TOKEN"]:
            discovered = discover_api_v1_repos(CONFIG["URL"], CONFIG["TOKEN"])
        elif CONFIG["USER"] and CONFIG["PASS"]:
            service_name = get_service_name(CONFIG["URL"])
            debug(f"[DEBUG] Detected Service Name: {service_name}")
            discovered = discover_v2_catalog(CONFIG["URL"], CONFIG["USER"], CONFIG["PASS"], service_name)
        else:
            print("Error: No authentication provided (Token or User/Pass) and no credentials found in ~/.docker/config.json")
            sys.exit(1)

        # Full repository names for skopeo (host + relative path)
        discovered = [f"{CONFIG['HOST']}/{r}" for r in discovered]

        debug(f"[INFO] Filtering by '{CONFIG['FILTER']}'")
        searched = filter_bundle_repos(discovered)

        # Optional sub-path restriction (from the -u URL path)
        if CONFIG["PREFIX"]:
            debug(f"[INFO] Restricting to prefix '{CONFIG['PREFIX']}'")
            prefix_match = f"{CONFIG['HOST']}/{CONFIG['PREFIX']}"
            searched = [r for r in searched if r.startswith(prefix_match)]

        repos_to_process.extend(searched)

        # Optional catalog detection (name-based guess, list-tags only) for the
        # imagesetconfig; skipped when --catalog was given explicitly.
        if CONFIG["OC_MIRROR_V2"] and not CONFIG["CATALOG_EXPLICIT"]:
            debug("[INFO] Detecting operator catalog repositories by name...")
            CONFIG["CATALOG_CANDIDATES"] = detect_catalogs(discovered)

    # Deduplicate while preserving order
    seen = set()
    repos_to_process = [r for r in repos_to_process
                        if not (r in seen or seen.add(r))]

    if not repos_to_process:
        print("[!] No bundle repositories found. Exiting.")
        sys.exit(0)

    debug(f"[INFO] Processing {len(repos_to_process)} bundle repository/repositories")

    # 3. LIST TAGS + INSPECT + PARSE
    results = []
    for repo in repos_to_process:
        results.extend(process_repo(repo))

    # 4. REPORTING
    if results:
        print_report(results)
        if CONFIG["OUTPUT_CSV"]:
            export_csv(results, CONFIG["OUTPUT_CSV"])
        if CONFIG["OC_MIRROR_V2"]:
            export_oc_mirror_yaml(results, CONFIG["OC_MIRROR_V2"])
    else:
        print("\n[!] No operator bundle versions could be extracted.")
        sys.exit(0)

if __name__ == "__main__":
    main()