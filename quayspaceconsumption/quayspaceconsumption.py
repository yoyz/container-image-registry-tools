#!/usr/bin/env python3
# ==============================================================================
# quayspaceconsumption.py
# ------------------------------------------------------------------------------
# Features:
# 1. Calculates storage usage with deduplication (Architecture & Repo level).
# 2. Hybrid Auth: Supports Token (API v1) and User/Pass (Registry V2).
# 3. Auto-Auth: Detects credentials in ~/.docker/config.json if not provided.
# 4. Robustness: Pagination support for Tags & Catalog; "Zombie" image fix.
# 5. Output: Console summary + CSV Export (-o).
# 6. Debugging: Full Curl command output generation (--curl-debug).
# 7. Help: Usage and examples via -h/--help.
# ==============================================================================

# This tool was mainly engineer thru AI tools with lots of manual tweaking here and there.
# it has only been tested on on premise quay3
# it should not harm your quay because it only do GET/HEAD action

from urllib.parse import quote_plus, unquote
from collections import defaultdict
import requests, json, getopt, sys, re, signal, os, base64, csv
import urllib3

# Suppress SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global Configuration
CONFIG = {
    "URL": "",
    "TOKEN": "",
    "USER": "",
    "PASS": "",
    "DEBUG": False,
    "CURL": False,
    "REPO_FILE": "",
    "OUTPUT_CSV": ""
}

# Global Trackers
GLOBAL_BLOBS = set()
REPO_SUMMARY = {}
ARCH_BLOBS = defaultdict(set)

# --- SIGNAL HANDLING (Ctrl+C) ---
def signal_handler(sig, frame):
    print("\n\n[!] Interrupt received (Ctrl+C). Forcing Exit...")
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

def debug(msg):
    if CONFIG["DEBUG"]: print(msg)

def format_size(size_bytes):
    mib = size_bytes / 1024 / 1024
    return f"{mib:.2f}".replace('.', ',')

def print_usage():
    script_name = os.path.basename(sys.argv[0])
    print(f"""
{script_name}
============================
Calculates physical storage usage for Quay/Docker registries by handling
deduplication, multi-arch manifests, and pagination.

Usage:
  python3 {script_name} -u <URL> [OPTIONS]

Options:
  -u <URL>        Registry URL (required, e.g., https://quay.example.com)
  -t <TOKEN>      OAuth Token (Recommended for Quay, uses API v1)
  -U <USER>       Username (for Standard Registry V2 access)
  -P <PASS>       Password (for Standard Registry V2 access)
  -f <FILE>       File containing list of repositories to scan (one per line)
  -o <FILE>       Export results to a CSV file
  -d              Enable debug output
  --curl-debug    Print equivalent curl commands for debugging
  -h, --help      Show this help message and exit

Authentication Modes:
  1. Token Mode (-t): Uses Quay API v1. Best for Quay. Handles large histories best.
  2. Credentials (-U/-P): Uses Registry V2 API. Best for non-Quay or standard auth.
  3. Auto-Auth: If no auth flags are provided, the script attempts to read
     credentials from ~/.docker/config.json or standard locations.

Examples:
  # 1. Scan entire registry using a Token (Best for Quay)
  python3 {script_name} -u https://quay.example.com -t "Mh2y..."

  # 2. Scan specific repos listed in a file using User/Pass
  python3 {script_name} -u https://registry.lab.com -U admin -P password -f my_repos.txt

  # 3. Auto-detect credentials from docker config and export to CSV
  python3 {script_name} -u https://quay.io -o report.csv

  # 4. Debug connection issues with curl output
  python3 {script_name} -u https://quay.example.com -t <token> --curl-debug
""")
    sys.exit(0)

def print_curl(url, headers, depth=0, label="REQ"):
    if not CONFIG["CURL"]: return
    indent = "    " * (depth + 1)
    header_str = "".join([f' -H "{k}: {v}"' for k, v in headers.items()])
    print(f"{indent}[CURL {label}] curl -X GET{header_str} \"{url}\" -k")

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
        
        # Try exact match first, then try appending/removing https://
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

        # Handle 'auth' string (Base64 encoded "user:pass")
        if "auth" in reg_data:
            try:
                decoded_auth = base64.b64decode(reg_data["auth"]).decode('utf-8')
                if ":" in decoded_auth:
                    username, password = decoded_auth.split(":", 1)
                    return {"username": username, "password": password}
            except Exception: pass

        # Handle explicit keys
        if "username" in reg_data and "password" in reg_data:
            return {
                "username": reg_data["username"],
                "password": reg_data["password"]
            }

    except Exception:
        pass

    return {}

# --- CORE FETCHING ---

def fetch_manifest_data(url, headers, depth, label):
    """Generic fetcher that tries standard and then degraded headers."""
    # 1. Try Complex (Multi-Arch)
    print_curl(url, headers, depth, f"{label} (Complex)")
    try:
        resp = requests.get(url, headers=headers, verify=False)
        if resp.status_code == 200: return resp.json()
    except Exception: pass

    # 2. Try Simple V2
    simple_headers = headers.copy()
    simple_headers["Accept"] = "application/vnd.docker.distribution.manifest.v2+json"
    print_curl(url, simple_headers, depth, f"{label} (Simple)")
    try:
        resp = requests.get(url, headers=simple_headers, verify=False)
        if resp.status_code == 200: return resp.json()
    except Exception: pass

    # 3. Try Any
    any_headers = headers.copy()
    any_headers["Accept"] = "*/*"
    print_curl(url, any_headers, depth, f"{label} (Any)")
    try:
        resp = requests.get(url, headers=any_headers, verify=False)
        if resp.status_code == 200: return resp.json()
    except Exception: pass
    
    return None

def recurse_manifest(ns, repo_decoded, digest_or_tag, current_token, use_v2_api, repo_blobs, depth=0, arch="unknown"):
    """
    Returns True if manifest was successfully fetched and processed.
    Returns False if fetch failed (404/Auth).
    """
    indent = "    " * (depth + 1)
    
    headers = {
        "Authorization": f"Bearer {current_token}",
        "Accept": "application/vnd.docker.distribution.manifest.list.v2+json, "
                  "application/vnd.oci.image.index.v1+json, "
                  "application/vnd.docker.distribution.manifest.v2+json, "
                  "application/vnd.oci.image.manifest.v1+json"
    }

    body = None
    origin = "V1" if not use_v2_api else "V2"

    if not use_v2_api:
        # API v1 Path
        repo_enc = quote_plus(repo_decoded)
        url = f"{CONFIG['URL']}/api/v1/repository/{ns}/{repo_enc}/manifest/{digest_or_tag}"
        print_curl(url, headers, depth, "V1")
        try:
            resp = requests.get(url, headers=headers, verify=False)
            if resp.status_code == 200 and "error" not in resp.json():
                body = resp.json()
            else:
                use_v2_api = True # Failover
        except Exception: use_v2_api = True

    if use_v2_api:
        # Registry V2 Path
        origin = "V2"
        url = f"{CONFIG['URL']}/v2/{ns}/{repo_decoded}/manifests/{digest_or_tag}"
        body = fetch_manifest_data(url, headers, depth, "V2")

    if not body:
        if depth == 0:
             debug(f"{indent}[WARN] Failed to fetch manifest for {digest_or_tag}")
        return False 

    is_list = body.get("is_manifest_list") is True or "list" in body.get("mediaType", "") or "index" in body.get("mediaType", "")

    if is_list:
        debug(f"{indent}[DEBUG] ({origin}) List: {digest_or_tag}")
        manifests = body.get("manifests", [])
        if not manifests and "manifest_data" in body:
            try: manifests = json.loads(body["manifest_data"]).get("manifests", [])
            except Exception: pass

        if manifests:
            for m in manifests:
                sub_digest = m.get("digest")
                platform = m.get("platform", {})
                sub_arch = platform.get("architecture", "unknown")
                if "os" in platform: sub_arch = f"{platform.get('os')}/{sub_arch}"
                recurse_manifest(ns, repo_decoded, sub_digest, current_token, use_v2_api, repo_blobs, depth + 1, sub_arch)
    else:
        arch_label = f" ({arch})" if arch != "unknown" else ""
        debug(f"{indent}[DEBUG] ({origin}) Image{arch_label}: {digest_or_tag}")
        
        layers = body.get("layers", [])
        if not layers and "manifest_data" in body:
            try: layers = json.loads(body["manifest_data"]).get("layers", [])
            except Exception: pass

        for layer in layers:
            b_hash = layer.get("blob_digest") or layer.get("digest") or layer.get("hash")
            b_size = layer.get("compressed_size") or layer.get("size") or 0
            
            if b_hash and isinstance(b_size, int):
                blob_tuple = (b_hash, b_size)
                
                if blob_tuple not in repo_blobs:
                    if CONFIG["DEBUG"]:
                         print(f"{indent}    >> Blob: {b_hash} | Size: {format_size(b_size)} MiB")
                         blob_url = f"{CONFIG['URL']}/v2/{ns}/{repo_decoded}/blobs/{b_hash}"
                         blob_headers = {"Authorization": f"Bearer {current_token}", "Accept": "*/*"}
                         print_curl(blob_url, blob_headers, depth + 1, "BLOB")

                    repo_blobs.add(blob_tuple)
                    GLOBAL_BLOBS.add(blob_tuple)
                    ARCH_BLOBS[arch].add(blob_tuple)
    
    return True 

# --- TOKEN MODE LOGIC ---

def discover_api_v1_repos(base_url, token):
    debug("[INFO] Discovering repositories via API v1...")
    discovered_repos = []
    try:
        resp = requests.get(f"{base_url}/api/v1/user/", headers={"Authorization": f"Bearer {token}"}, verify=False)
        data = resp.json()
        orgs = [o['name'] for o in data.get('organizations', [])]
        if 'username' in data: orgs.append(data['username'])

        for org in orgs:
            r_resp = requests.get(f"{base_url}/api/v1/repository", params={'namespace': org}, headers={"Authorization": f"Bearer {token}"}, verify=False)
            if r_resp.status_code == 200:
                repos = r_resp.json().get('repositories', [])
                for r in repos:
                    discovered_repos.append(f"{org}/{r['name']}")
                debug(f"[INFO] Found {len(repos)} in namespace '{org}'")
    except Exception as e:
        print(f"[ERROR] API v1 Discovery failed: {e}")
        sys.exit(1)
    
    discovered_repos.sort()
    return discovered_repos

def process_api_v1_repos(repos_list, base_url, token):
    repos_list.sort()
    debug(f"[INFO] Processing {len(repos_list)} repositories...")
    
    for full_repo in repos_list:
        print(f"Scanning: {full_repo}")
        try:
            ns, repo_name = full_repo.split('/', 1)
            repo_enc = quote_plus(repo_name)
        except ValueError: continue

        items_to_process = set()
        
        # V1 Pagination
        page = 1
        has_additional = True
        
        while has_additional:
            try:
                url = f"{base_url}/api/v1/repository/{ns}/{repo_enc}/tag/?limit=100&page={page}"
                resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False)
                
                if resp.status_code == 200:
                    data = resp.json()
                    tags = data.get('tags', []) or []
                    has_additional = data.get('has_additional', False)
                    for t in tags:
                        if 'manifest_digest' in t:
                            items_to_process.add(t['manifest_digest'])
                    page += 1
                else:
                    has_additional = False
            except Exception:
                has_additional = False

        repo_blobs = set()
        for item in items_to_process:
            recurse_manifest(ns, repo_name, item, token, False, repo_blobs)

        if repo_blobs:
            size = sum(s for _, s in repo_blobs)
            print(f"  >> Unique Repo Footprint: {format_size(size)} MiB")
            REPO_SUMMARY[full_repo] = format_size(size)

# --- USER/PASS MODE LOGIC ---

def get_service_name(base_url):
    try:
        resp = requests.get(f"{base_url}/v2/", verify=False, timeout=10)
        auth_header = resp.headers.get("Www-Authenticate", "")
        m = re.search(r'service="([^"]+)"', auth_header)
        if m: return m.group(1)
        return base_url.replace("https://", "").replace("http://", "").split("/")[0]
    except Exception:
        return base_url.replace("https://", "").replace("http://", "").split("/")[0]

def discover_v2_catalog(base_url, user, password, service_name):
    debug(f"[INFO] Starting V2 Discovery (Service: {service_name})...")
    discovered_repos = []
    
    cat_token = ""
    try:
        params = {'service': service_name}
        auth_resp = requests.get(f"{base_url}/v2/auth", auth=(user, password), params=params, verify=False)
        if auth_resp.status_code == 200:
            cat_token = auth_resp.json().get('token') or auth_resp.json().get('access_token')
    except Exception: pass

    if cat_token:
        next_url = f"{base_url}/v2/_catalog?n=1000"
        while next_url:
            try:
                cat_resp = requests.get(next_url, headers={"Authorization": f"Bearer {cat_token}"}, verify=False)
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
                else: next_url = None
            except Exception: next_url = None

    if not discovered_repos:
        debug("[INFO] Catalog empty/blocked. Using Search fallback...")
        try:
            params = {'query': ''} 
            resp = requests.get(f"{base_url}/api/v1/find/repositories", auth=(user, password), params=params, verify=False)
            if resp.status_code == 200:
                results = resp.json().get('results', []) or resp.json().get('repositories', [])
                for r in results:
                    name = r.get('full_name') or f"{r.get('namespace', {}).get('name')}/{r.get('name')}"
                    if name and '/' in name: discovered_repos.append(name)
        except Exception: pass
    
    discovered_repos.sort()
    return discovered_repos

def process_v2_repos(repos_list, base_url, user, password, service_name):
    repos_list.sort()
    debug(f"[INFO] Processing {len(repos_list)} repositories...")
    
    for full_repo in repos_list:
        print(f"Scanning: {full_repo}")
        try:
            ns, repo_name = full_repo.split('/', 1)
        except ValueError: continue

        scope = f"repository:{full_repo}:pull"
        repo_token = ""
        try:
            params = {'service': service_name, 'scope': scope}
            r = requests.get(f"{base_url}/v2/auth", auth=(user, password), params=params, verify=False)
            if r.status_code == 200:
                repo_token = r.json().get('token') or r.json().get('access_token')
            else:
                debug(f"  [ERROR] Auth denied for {full_repo}")
                continue
        except Exception: continue

        work_queue = {} 

        # Tag Pagination
        next_tag_url = f"{base_url}/v2/{full_repo}/tags/list?n=100"

        while next_tag_url:
            try:
                r = requests.get(next_tag_url, headers={"Authorization": f"Bearer {repo_token}"}, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    tags = data.get('tags', []) or []
                    if CONFIG["DEBUG"]: debug(f"  [DEBUG] Fetched {len(tags)} tags from page...")

                    for tag in tags:
                        h_headers = {
                            "Authorization": f"Bearer {repo_token}", 
                            "Accept": "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json"
                        }
                        h = requests.head(f"{base_url}/v2/{full_repo}/manifests/{tag}", headers=h_headers, verify=False)
                        digest = h.headers.get("Docker-Content-Digest")
                        
                        if digest:
                            work_queue[digest] = tag
                        else:
                            work_queue[tag] = tag

                    link_header = r.headers.get("Link")
                    next_tag_url = None
                    if link_header:
                        match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
                        if match:
                            next_link = match.group(1)
                            if next_link.startswith("http"):
                                next_tag_url = next_link
                            else:
                                next_tag_url = f"{base_url}{next_link}"
                else:
                    next_tag_url = None
            except Exception:
                next_tag_url = None
        
        # Process blobs with zombie fallback
        repo_blobs = set()
        for key, tag_backup in work_queue.items():
            success = recurse_manifest(ns, repo_name, key, repo_token, True, repo_blobs)
            if not success and key != tag_backup:
                debug(f"  [WARN] Digest fetch failed. Retrying with Tag: {tag_backup}")
                recurse_manifest(ns, repo_name, tag_backup, repo_token, True, repo_blobs)

        if repo_blobs:
            size = sum(s for _, s in repo_blobs)
            print(f"  >> Unique Repo Footprint: {format_size(size)} MiB")
            REPO_SUMMARY[full_repo] = format_size(size)

# --- MAIN ENTRY ---
def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:t:U:P:f:o:dh", ["curl-debug", "help"])
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    for o, a in opts:
        if o == "-u": CONFIG["URL"] = a.rstrip('/')
        elif o == "-t": CONFIG["TOKEN"] = a
        elif o == "-U": CONFIG["USER"] = a
        elif o == "-P": CONFIG["PASS"] = a
        elif o == "-d": CONFIG["DEBUG"] = True
        elif o == "-f": CONFIG["REPO_FILE"] = a
        elif o == "-o": CONFIG["OUTPUT_CSV"] = a
        elif o == "-h" or o == "--help": print_usage()
        elif o == "--curl-debug": 
            CONFIG["DEBUG"] = True
            CONFIG["CURL"] = True

    if not CONFIG["URL"]:
        print("Error: -u <URL> is required")
        print(f"Try 'python3 {os.path.basename(sys.argv[0])} --help' for more information.")
        sys.exit(1)
        
    if not CONFIG["URL"].startswith("http"):
        CONFIG["URL"] = "https://" + CONFIG["URL"]

    # --- AUTO-AUTH LOGIC ---
    if not CONFIG["TOKEN"] and (not CONFIG["USER"] or not CONFIG["PASS"]):
        clean_host = CONFIG["URL"].replace("https://", "").replace("http://", "")
        # Common locations for docker config
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

    # 1. RESOLVE REPOSITORIES
    repos_to_scan = []
    
    if CONFIG["REPO_FILE"]:
        try:
            with open(CONFIG["REPO_FILE"], 'r') as f:
                # Strip leading slashes to prevent auth errors
                repos_to_scan = [line.strip().lstrip('/') for line in f if line.strip() and not line.startswith('#')]
            debug(f"[INFO] Loaded {len(repos_to_scan)} repositories from file.")
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

    # 2. EXECUTE MODE
    if CONFIG["TOKEN"]:
        if not repos_to_scan:
            repos_to_scan = discover_api_v1_repos(CONFIG["URL"], CONFIG["TOKEN"])
        process_api_v1_repos(repos_to_scan, CONFIG["URL"], CONFIG["TOKEN"])
        
    elif CONFIG["USER"] and CONFIG["PASS"]:
        service_name = get_service_name(CONFIG["URL"])
        debug(f"[DEBUG] Detected Service Name: {service_name}")
        if not repos_to_scan:
            repos_to_scan = discover_v2_catalog(CONFIG["URL"], CONFIG["USER"], CONFIG["PASS"], service_name)
        process_v2_repos(repos_to_scan, CONFIG["URL"], CONFIG["USER"], CONFIG["PASS"], service_name)
        
    else:
        print("Error: No authentication provided (Token or User/Pass) and no credentials found in ~/.docker/config.json")
        sys.exit(1)

    # 3. REPORTING
    print("\nARCHITECTURE BREAKDOWN (Deduplicated within Arch)")
    print("-" * 64)
    for arch, blobs in sorted(ARCH_BLOBS.items()):
        arch_size = sum(size for _, size in blobs)
        print(f"{arch:<20} | {format_size(arch_size)} MiB")

    print("\nREPOSITORY SUMMARY")
    print("-" * 64)
    for repo, size in sorted(REPO_SUMMARY.items(), key=lambda x: float(x[1].replace(',', '.')), reverse=True):
        print(f"{repo:<50} | {size} MiB")

    total_bytes = sum(size for _, size in GLOBAL_BLOBS)
    final_str = format_size(total_bytes)
    print("-" * 64)
    print(f"FINAL TOTAL (Deduplicated physical storage): {final_str} MiB")

    # 4. CSV EXPORT
    if CONFIG["OUTPUT_CSV"]:
        try:
            with open(CONFIG["OUTPUT_CSV"], 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Repository", "Size (MiB)"])
                for repo, size in sorted(REPO_SUMMARY.items(), key=lambda x: float(x[1].replace(',', '.')), reverse=True):
                    writer.writerow([repo, size])
                writer.writerow([])
                writer.writerow(["Total Deduplicated", final_str])
            print(f"\n[INFO] Report saved to {CONFIG['OUTPUT_CSV']}")
        except Exception as e:
            print(f"[ERROR] Failed to write CSV: {e}")

if __name__ == "__main__":
    main()

