import requests
import argparse
import sys
import json
import urllib.parse
import time
import ssl
import socket

try:
    import yaml
except ImportError:
    yaml = None

__version__ = "0.24"

class QuayClient:
    def __init__(self, url, token, debug=False):
        url = url.strip('/')
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
            
        self.url = url
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.debug = debug

    def _request(self, method, path, max_retries=10, **kwargs):
        full_url = f"{self.url}{path}"
        
        if self.debug:
            curl_cmd = f"curl -k -s -X {method} '{full_url}"
            if 'params' in kwargs and kwargs['params']:
                qs = urllib.parse.urlencode(kwargs['params'])
                curl_cmd += f"?{qs}"
            curl_cmd += "'"
            for k, v in self.headers.items():
                curl_cmd += f" -H '{k}: {v}'"
            if 'json' in kwargs:
                curl_cmd += f" -d '{json.dumps(kwargs['json'])}'"
            print(f"\n[DEBUG CMD] {curl_cmd}")

        for attempt in range(max_retries):
            resp = requests.request(method, full_url, headers=self.headers, **kwargs)
            
            if self.debug:
                print(f"[DEBUG RSP] HTTP {resp.status_code}: {resp.text}")
                
            if resp.status_code >= 500:
                if attempt < max_retries - 1:
                    sleep_time = 2 ** attempt
                    print(f"    ⚠️  HTTP {resp.status_code} received. Retrying in {sleep_time}s (Attempt {attempt + 1}/{max_retries})...")
                    time.sleep(sleep_time)
                    continue
                else:
                    break
            
            break
            
        return resp

    def get_all_namespaces(self):
        namespaces = []
        if self.debug: print("[DEBUG] Fetching all superuser users & orgs to find namespaces...")
        
        resp_users = self._request("GET", "/api/v1/superuser/users/")
        if resp_users.status_code == 200:
            namespaces.extend([u['username'] for u in resp_users.json().get('users', [])])
        else:
            print(f"    ⚠️  Failed to fetch users (HTTP {resp_users.status_code}). Check if token is valid and has superuser rights.")
            
        resp_orgs = self._request("GET", "/api/v1/superuser/organizations/")
        if resp_orgs.status_code == 200:
            namespaces.extend([o['name'] for o in resp_orgs.json().get('organizations', [])])
        else:
            print(f"    ⚠️  Failed to fetch organizations (HTTP {resp_orgs.status_code}). Check if token is valid and has superuser rights.")
            
        return namespaces

    def get_all_repos(self, namespace=None):
        repos = []
        namespaces_to_check = [namespace] if namespace else self.get_all_namespaces()
        
        if not namespaces_to_check:
            print("❌ No namespaces found to query. Please provide --namespace manually or check your token permissions.")
            sys.exit(1)
            
        for ns in namespaces_to_check:
            next_page = ""
            while True:
                params = {"namespace": ns}
                if next_page: params["next_page"] = next_page
                    
                resp = self._request("GET", "/api/v1/repository", params=params)
                resp.raise_for_status()
                data = resp.json()
                
                for r in data.get('repositories', []):
                    repos.append(f"{r['namespace']}/{r['name']}")
                    
                next_page = data.get('next_page')
                if not next_page: break
        return repos

def list_action(args):
    client = QuayClient(args.src_url, args.src_token, debug=args.debug)
    try:
        if not args.all and not args.namespace:
            print("❌ Please provide either --namespace <name> or --all to list repositories.")
            sys.exit(1)
            
        print(f"--> Discovery Mode: Fetching repositories from {args.src_url}...")
        repos = client.get_all_repos(args.namespace)
        
        if not repos:
            print("❌ No repositories found.")
            sys.exit(1)
            
        with open(args.file, 'w') as f:
            for r in repos: f.write(f"{r}\n")
        print(f"✅ Exported {len(repos)} repo paths to {args.file}")
    except Exception as e:
        print(f"❌ Failed to list repositories: {e}")
        sys.exit(1)

def create_robot_action(args):
    client = QuayClient(args.tgt_url, args.tgt_token, debug=args.debug)
    with open(args.file, 'r') as f:
        namespaces = {line.split('/')[0] for line in f if '/' in line}
    
    for ns in namespaces:
        target_ns = f"{args.prefix}/{ns}" if args.prefix else ns
        print(f"--> Ensuring Org/Robot exists for: {target_ns}")
        try:
            resp = client._request("POST", "/api/v1/organization/", json={"name": target_ns, "email": f"{target_ns}@example.com"})
            if resp.status_code == 400 and "already exists" in resp.text.lower():
                print(f"    ℹ️  Org '{target_ns}' already exists.")
            else:
                resp.raise_for_status()
                print(f"    ✅ Org '{target_ns}' created.")

            resp = client._request("PUT", f"/api/v1/organization/{target_ns}/robots/{args.robot_name}")
            resp.raise_for_status()
            print(f"    ✅ Robot '{args.robot_name}' ready in {target_ns}")
        except requests.exceptions.HTTPError as e:
            print(f"    ❌ API Error: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            print(f"    ❌ Failed: {e}")

def list_robot_action(args):
    client = QuayClient(args.tgt_url, args.tgt_token, debug=args.debug)
    with open(args.file, 'r') as f:
        namespaces = {line.split('/')[0] for line in f if '/' in line}
    
    for ns in namespaces:
        target_ns = f"{args.prefix}/{ns}" if args.prefix else ns
        print(f"--> Listing robots for Org: {target_ns}")
        try:
            resp = client._request("GET", f"/api/v1/organization/{target_ns}/robots")
            if resp.status_code == 200:
                robots = resp.json().get('robots', [])
                if not robots:
                    print("    ℹ️  No robots found.")
                for r in robots:
                    print(f"    🤖 {r.get('name')}")
            elif resp.status_code == 404:
                print("    ℹ️  Org not found (404).")
            else:
                resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print(f"    ❌ API Error: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            print(f"    ❌ Failed: {e}")

def delete_robot_action(args):
    client = QuayClient(args.tgt_url, args.tgt_token, debug=args.debug)
    confirm = input(f"⚠️  DANGER: Delete robot '{args.robot_name}' from organizations in {args.file}? (y/N): ")
    if confirm.lower() != 'y':
        print("Aborted.")
        return

    with open(args.file, 'r') as f:
        namespaces = {line.split('/')[0] for line in f if '/' in line}
    
    for ns in namespaces:
        target_ns = f"{args.prefix}/{ns}" if args.prefix else ns
        print(f"🗑️  Deleting robot '{args.robot_name}' from: {target_ns}...")
        try:
            resp = client._request("DELETE", f"/api/v1/organization/{target_ns}/robots/{args.robot_name}")
            if resp.status_code in [202, 204]:
                print(f"    ✅ Deleted.")
            elif resp.status_code == 404:
                print(f"    ℹ️  Already deleted (404).")
            else:
                resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print(f"    ❌ API Error: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            print(f"    ❌ Failed: {e}")

def sync_action(args):
    tgt_client = QuayClient(args.tgt_url, args.tgt_token, debug=args.debug)
    with open(args.file, 'r') as f:
        repo_paths = [line.strip() for line in f if '/' in line]

    for path in repo_paths:
        src_ns, repo_name = path.split('/', 1)
        target_ns = f"{args.prefix}/{src_ns}" if args.prefix else src_ns
        full_target_path = f"{target_ns}/{repo_name}"
        
        local_sync_user = f"{target_ns}+{args.robot_name}"
        
        print(f"--> Configuring Mirror: {full_target_path}")
        try:
            repo_desc = f"{args.src_url.rstrip('/')}/{path}"

            repo_data = {
                "repository": repo_name, 
                "namespace": target_ns, 
                "visibility": args.visibility,
                "description": repo_desc
            }
            resp = tgt_client._request("POST", "/api/v1/repository", json=repo_data)
            if resp.status_code == 400 and "already exists" in resp.text.lower():
                print(f"    ℹ️  Repo already exists, ensuring mirror state...")
            else:
                resp.raise_for_status()

            put_data = {
                "repo_state": "MIRROR",
                "description": repo_desc
            }
            resp = tgt_client._request("PUT", f"/api/v1/repository/{full_target_path}", json=put_data)
            resp.raise_for_status()

            mirror_config = {
                "is_enabled": True,
                "external_reference": f"{args.src_url.replace('https://', '').replace('http://', '').strip('/')}/{path}",
                "external_registry_username": args.src_user,
                "external_registry_password": args.src_pass,
                "sync_interval": args.interval,
                "sync_start_date": "2024-01-01T00:00:00Z",
                "root_rule": {"rule_kind": "tag_glob_csv", "rule_value": ["*"]},
                "robot_username": local_sync_user
            }
            
            if args.insecure:
                mirror_config["external_registry_config"] = {"verify_tls": False}

            resp = tgt_client._request("POST", f"/api/v1/repository/{full_target_path}/mirror", json=mirror_config)
            
            if resp.status_code == 409:
                print(f"    ℹ️  Mirror configuration already exists. Updating...")
                resp = tgt_client._request("PUT", f"/api/v1/repository/{full_target_path}/mirror", json=mirror_config)
                resp.raise_for_status()
                print(f"    ✅ Success (Updated)")
            else:
                resp.raise_for_status()
                print(f"    ✅ Success (Created)")
                
        except requests.exceptions.HTTPError as e:
            print(f"    ❌ API Error: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            print(f"    ❌ Failed: {e}")

def sync_now_action(args):
    client = QuayClient(args.tgt_url, args.tgt_token, debug=args.debug)
    
    try:
        with open(args.file, 'r') as f:
            repo_paths = [line.strip() for line in f if '/' in line]
    except FileNotFoundError:
        print(f"❌ File {args.file} not found.")
        sys.exit(1)

    print(f"--> Triggering manual sync for {len(repo_paths)} repositories...\n")

    for path in repo_paths:
        src_ns, repo_name = path.split('/', 1)
        target_ns = f"{args.prefix}/{src_ns}" if args.prefix else src_ns
        full_target_path = f"{target_ns}/{repo_name}"
        
        try:
            if args.failed_only:
                status_resp = client._request("GET", f"/api/v1/repository/{full_target_path}/mirror", max_retries=1)
                if status_resp.status_code == 200:
                    current_status = status_resp.json().get('sync_status', 'UNKNOWN')
                    if current_status not in ["FAILED", "FAIL", "ERROR", "ABORTED"]:
                        print(f"⏩ {full_target_path}: Skipping (Status is {current_status})")
                        continue
                elif status_resp.status_code in [400, 404]:
                    print(f"⚪ {full_target_path}: Not a mirror or not found.")
                    continue
            
            print(f"⚡ {full_target_path}: Triggering sync...")
            resp = client._request("POST", f"/api/v1/repository/{full_target_path}/mirror/sync-now")
            
            if resp.status_code in [200, 201, 202, 204]:
                print(f"    ✅ Sync started successfully.")
            elif resp.status_code == 400 and "already syncing" in resp.text.lower():
                print(f"    ℹ️  Already syncing.")
            else:
                resp.raise_for_status()
                
        except requests.exceptions.HTTPError as e:
            print(f"    ❌ API Error: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            print(f"    ❌ Failed: {e}")

def cleanup_action(args):
    client = QuayClient(args.tgt_url, args.tgt_token, debug=args.debug)
    confirm = input(f"⚠️  DANGER: Delete repositories in {args.file} from {args.tgt_url}? (y/N): ")
    if confirm.lower() != 'y':
        print("Aborted.")
        return

    with open(args.file, 'r') as f:
        repo_paths = [line.strip() for line in f if '/' in line]

    for path in repo_paths:
        src_ns, repo_name = path.split('/', 1)
        target_ns = f"{args.prefix}/{src_ns}" if args.prefix else src_ns
        full_target_path = f"{target_ns}/{repo_name}"
        
        print(f"🗑️  Deleting: {full_target_path}...")
        try:
            resp = client._request("DELETE", f"/api/v1/repository/{full_target_path}")
            if resp.status_code in [202, 204]:
                print(f"    ✅ Deleted.")
            elif resp.status_code == 404:
                print(f"    ℹ️  Already deleted (404).")
            else:
                resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print(f"    ❌ API Error: {e.response.status_code} - {e.response.text}")
            

def status_action(args):
    client = QuayClient(args.tgt_url, args.tgt_token, debug=args.debug)
    repo_paths = []

    if args.all:
        print(f"--> Discovery Mode: Fetching ALL repositories from {args.tgt_url}...")
        repo_paths = client.get_all_repos(args.namespace)
    else:
        try:
            with open(args.file, 'r') as f:
                lines = [line.strip() for line in f if '/' in line]
                for path in lines:
                    src_ns, repo_name = path.split('/', 1)
                    target_ns = f"{args.prefix}/{src_ns}" if args.prefix else src_ns
                    repo_paths.append(f"{target_ns}/{repo_name}")
        except FileNotFoundError:
            print(f"❌ File {args.file} not found. Use --all to check all target repositories instead.")
            sys.exit(1)

    print(f"--> Checking mirror status for {len(repo_paths)} repositories...\n")
    
    counts = {"SUCCESS": 0, "FAILED": 0, "SYNCING": 0, "SCHEDULED": 0, "NEVER_RUN": 0, "NOT_MIRROR": 0, "OTHER": 0}

    for path in repo_paths:
        try:
            resp = client._request("GET", f"/api/v1/repository/{path}/mirror", max_retries=1)
            
            if resp.status_code == 200:
                data = resp.json()
                status = data.get('sync_status', 'UNKNOWN')
                
                if status in ["SUCCESS", "FINISHED", "PASSED"]:
                    icon, key = "✅", "SUCCESS"
                elif status in ["FAILED", "FAIL", "ERROR", "ABORTED"]:
                    icon, key = "❌", "FAILED"
                elif status in ["SYNCING", "SYNC_NOW", "RUNNING", "IN_PROGRESS"]:
                    icon, key = "🔄", "SYNCING"
                elif status in ["SCHEDULED", "PENDING"]:
                    icon, key = "⏳", "SCHEDULED"
                elif status == "NEVER_RUN":
                    icon, key = "🆕", "NEVER_RUN"
                else:
                    icon, key = "ℹ️", "OTHER"
                    
                counts[key] += 1
                print(f"{icon} {path}: {status}")
                
            elif resp.status_code in [400, 404]:
                counts["NOT_MIRROR"] += 1
                print(f"⚪ {path}: NOT A MIRROR (or not found)")
            else:
                counts["OTHER"] += 1
                print(f"⚠️  {path}: ERROR HTTP {resp.status_code}")
                
        except Exception as e:
            counts["OTHER"] += 1
            print(f"⚠️  {path}: FAILED TO QUERY ({e})")

    print("\n--- Mirror Status Summary ---")
    for status, count in counts.items():
        if count > 0:
            print(f"{status}: {count}")

def check_https_connection(host, port):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                pass
        return True
    except ssl.SSLError:
        return False
    except Exception:
        return False

def get_cert_action(args):
    url = args.url.strip('/')
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
        
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    
    print(f"--> Fetching certificate chain from {host}:{port}...\n")
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        pem_chain = []

        with socket.create_connection((host, int(port)), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                if hasattr(ssock, 'get_unverified_chain'):
                    chain = ssock.get_unverified_chain()
                    if not chain:
                        print("❌ No certificates returned by the server.")
                        sys.exit(1)
                    for cert in chain:
                        pem_cert = ssl.DER_cert_to_PEM_cert(cert)
                        pem_chain.append(pem_cert)
                else:
                    cert = ssock.getpeercert(binary_form=True)
                    pem_chain.append(ssl.DER_cert_to_PEM_cert(cert))
                    print("⚠️ Note: Python < 3.10 detected. Only the peer certificate was fetched.")

        cert_pem = "\n".join(pem_chain)
        print(cert_pem)
        print("")

        trusted = check_https_connection(host, port)
        if not trusted:
            print("ℹ️  This server certificate is NOT trusted locally.")
            print("   You might want to add it to your system trust store by adding it to:")
            print("   /etc/pki/ca-trust/source/anchors/")
            print("   and running 'sudo update-ca-trust'")
        else:
            print("✅ This server certificate is trusted locally.")
            
        if args.out:
            with open(args.out, 'w') as f:
                f.write(cert_pem)
            print(f"\n✅ Saved certificate to {args.out}")

    except Exception as e:
        print(f"❌ Error: Could not retrieve certificates from {host} on port {port}.")
        print(f"Details: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        print(f"--- Quay Mirror Tool v{__version__} ---")
        
        argv = sys.argv[1:]
        config_file = None
        
        if '-c' in argv:
            config_file = argv[argv.index('-c') + 1]
        elif '--config' in argv:
            config_file = argv[argv.index('--config') + 1]

        config_args = []
        if config_file:
            if yaml is None:
                print("❌ Error: PyYAML is not installed. Please run 'pip install pyyaml' to use YAML config files.")
                sys.exit(1)
            try:
                with open(config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
                
                if config_data:
                    for k, v in config_data.items():
                        key = k.replace('_', '-')
                        if isinstance(v, bool):
                            if v: config_args.append(f"--{key}")
                        else:
                            config_args.extend([f"--{key}", str(v)])
            except Exception as e:
                print(f"❌ Error reading config file {config_file}: {e}")
                sys.exit(1)

        commands = ['list', 'create-robot', 'list-robot', 'delete-robot', 'sync', 'sync-now', 'cleanup', 'status', 'get-cert']
        cmd_index = -1
        for i, arg in enumerate(argv):
            if arg in commands:
                cmd_index = i
                break
                
        if cmd_index != -1 and config_args:
            argv = argv[:cmd_index+1] + config_args + argv[cmd_index+1:]
        elif config_args:
            argv = config_args + argv

        parser = argparse.ArgumentParser(description=f"Quay Mirror Automation v{__version__}")
        
        parent_parser = argparse.ArgumentParser(add_help=False)
        parent_parser.add_argument("-d", "--debug", action="store_true", help="Print debug curl commands and raw responses")
        parent_parser.add_argument("-c", "--config", help="Path to YAML configuration file")

        subparsers = parser.add_subparsers(dest="command")

        p_list = subparsers.add_parser("list", parents=[parent_parser])
        p_list.add_argument("--src-url", required=True)
        p_list.add_argument("--src-token", required=True)
        p_list.add_argument("--namespace", help="Optional: filter source namespace")
        p_list.add_argument("--all", action="store_true", help="Fetch ALL repositories from the source")
        p_list.add_argument("--file", default="repos.txt")

        p_create_robot = subparsers.add_parser("create-robot", parents=[parent_parser])
        p_create_robot.add_argument("--tgt-url", required=True)
        p_create_robot.add_argument("--tgt-token", required=True)
        p_create_robot.add_argument("--file", default="repos.txt")
        p_create_robot.add_argument("--prefix", help="Target namespace prefix")
        p_create_robot.add_argument("--robot-name", default="mirrorbot")

        p_list_robot = subparsers.add_parser("list-robot", parents=[parent_parser])
        p_list_robot.add_argument("--tgt-url", required=True)
        p_list_robot.add_argument("--tgt-token", required=True)
        p_list_robot.add_argument("--file", default="repos.txt")
        p_list_robot.add_argument("--prefix", help="Target namespace prefix")

        p_delete_robot = subparsers.add_parser("delete-robot", parents=[parent_parser])
        p_delete_robot.add_argument("--tgt-url", required=True)
        p_delete_robot.add_argument("--tgt-token", required=True)
        p_delete_robot.add_argument("--file", default="repos.txt")
        p_delete_robot.add_argument("--prefix", help="Target namespace prefix")
        p_delete_robot.add_argument("--robot-name", default="mirrorbot")

        p_sync = subparsers.add_parser("sync", parents=[parent_parser])
        p_sync.add_argument("--src-url", required=True)
        p_sync.add_argument("--tgt-url", required=True)
        p_sync.add_argument("--tgt-token", required=True)
        p_sync.add_argument("--file", default="repos.txt")
        p_sync.add_argument("--prefix", help="Target namespace prefix")
        p_sync.add_argument("--src-user", required=True)
        p_sync.add_argument("--src-pass", required=True)
        p_sync.add_argument("--robot-name", default="mirrorbot")
        p_sync.add_argument("--interval", type=int, default=86400)
        p_sync.add_argument("--visibility", default="private")
        p_sync.add_argument("--insecure", action="store_true", help="Disable TLS verification for the source registry")

        p_sync_now = subparsers.add_parser("sync-now", parents=[parent_parser])
        p_sync_now.add_argument("--tgt-url", required=True)
        p_sync_now.add_argument("--tgt-token", required=True)
        p_sync_now.add_argument("--file", default="repos.txt")
        p_sync_now.add_argument("--prefix", help="Target namespace prefix")
        p_sync_now.add_argument("--failed-only", action="store_true", help="Only trigger sync if the current status is FAILED or ERROR")

        p_clean = subparsers.add_parser("cleanup", parents=[parent_parser])
        p_clean.add_argument("--tgt-url", required=True)
        p_clean.add_argument("--tgt-token", required=True)
        p_clean.add_argument("--file", default="repos.txt")
        p_clean.add_argument("--prefix", help="Target namespace prefix")

        p_status = subparsers.add_parser("status", parents=[parent_parser])
        p_status.add_argument("--tgt-url", required=True)
        p_status.add_argument("--tgt-token", required=True)
        p_status.add_argument("--file", default="repos.txt", help="File to read repos from (default: repos.txt)")
        p_status.add_argument("--prefix", help="Target namespace prefix")
        p_status.add_argument("--all", action="store_true", help="Ignore file and check ALL accessible repos on the target")
        p_status.add_argument("--namespace", help="Optional: filter by namespace if using --all")

        p_cert = subparsers.add_parser("get-cert", parents=[parent_parser])
        p_cert.add_argument("--url", required=True, help="Registry URL to fetch cert from")
        p_cert.add_argument("--out", help="Save output to this file")

        args, unknown = parser.parse_known_args(argv)
        
        if hasattr(args, 'command') and args.command and unknown:
            ignored_flags = [flag for flag in unknown if flag.startswith('-')]
            if ignored_flags:
                print(f"    ℹ️  Ignored unused parameters from config for '{args.command}': {', '.join(ignored_flags)}\n")

        func_map = {
            "list": list_action, 
            "create-robot": create_robot_action, 
            "list-robot": list_robot_action,
            "delete-robot": delete_robot_action,
            "sync": sync_action, 
            "sync-now": sync_now_action,
            "cleanup": cleanup_action,
            "status": status_action,
            "get-cert": get_cert_action
        }
        
        if args.command in func_map:
            func_map[args.command](args)
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n\n🛑 Interrupted by user. Exiting cleanly...")
        sys.exit(130)
