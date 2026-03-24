#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import tempfile
import shutil

def check_auth_file(provided_auth_file):
    if provided_auth_file:
        if os.path.isfile(provided_auth_file):
            return provided_auth_file
        else:
            print(f"Error: Provided AUTH_FILE '{provided_auth_file}' does not exist.")
            sys.exit(1)
            
    standard_locations = [
        os.path.expanduser("~/.docker/config.json"),
        os.path.expanduser("~/.containers/auth.json"),
        os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/run/user/1000"), "containers/auth.json")
    ]

    for loc in standard_locations:
        if os.path.isfile(loc):
            print(f"Using found authentication file: {loc}")
            return loc

    print("Error: No credential file found.")
    print("Please provide one using the --authfile argument or ensure credentials exist in one of these standard locations:")
    for loc in standard_locations:
        print(f"  - {loc}")
    sys.exit(1)

def read_and_validate_images(images_file):
    if not os.path.isfile(images_file):
        print(f"Error: Images file '{images_file}' not found.")
        sys.exit(1)
        
    images = []
    with open(images_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if '/' not in line:
                    print("Error: Image file format is incorrect. Images must be fully qualified (FQDN/path:tag).")
                    print(f"First invalid image found: {line}")
                    sys.exit(1)
                
                domain_part = line.split('/')[0]
                if '.' not in domain_part and ':' not in domain_part and domain_part != "localhost":
                    print("Error: Image file format is incorrect. Missing FQDN in image name.")
                    print(f"First invalid image found: {line}")
                    sys.exit(1)
                
                last_part = line.split('/')[-1]
                if ':' not in last_part and '@' not in last_part:
                    print("Error: Image file format is incorrect. Missing tag or digest.")
                    print(f"First invalid image found: {line}")
                    sys.exit(1)

                images.append(line)
    return images

def generate_image_set_config(images, filepath, is_v2):
    api_version = "mirror.openshift.io/v2alpha1" if is_v2 else "mirror.openshift.io/v1alpha2"
    
    yaml_content = f"kind: ImageSetConfiguration\n"
    yaml_content += f"apiVersion: {api_version}\n"
    yaml_content += "mirror:\n"
    yaml_content += "  additionalImages:\n"
    
    for img in images:
        yaml_content += f"  - name: {img}\n"
        
    with open(filepath, 'w') as f:
        f.write(yaml_content)

def main():
    parser = argparse.ArgumentParser(description="Mirror images using oc-mirror")
    parser.add_argument("-i", "--images", help="Path to the file containing the list of images to generate a config")
    parser.add_argument("-c", "--config", help="Path to an existing ImageSetConfiguration YAML (for Phase 2 air-gapped execution)")
    parser.add_argument("-d", "--dest", help="Destination registry. Required for --mirror and --disk-to-mirror.")
    parser.add_argument("-a", "--authfile", help="Path to a custom JSON authentication file")
    
    parser.add_argument("--dest-tls-verify", choices=['true', 'false'], default='true', help="Enable or disable TLS verification for destination (default: true)")
    parser.add_argument("--generate", metavar="FILENAME", help="Generate the ImageSetConfig YAML file to the specified path")
    parser.add_argument("--v2", action="store_true", help="Format config for v2 and append the --v2 flag to the oc-mirror command")
    parser.add_argument("--dry-run", action="store_true", help="Display the command to be run without executing it")
    
    parser.add_argument("--imagedir", help="Path to the local directory for disconnected mirroring (will be created if it doesn't exist)")
    
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("--mirror", action="store_true", help="Launch a direct mirror-to-mirror process")
    action_group.add_argument("--mirror-to-disk", action="store_true", help="Mirror images from source registry to a local directory")
    action_group.add_argument("--disk-to-mirror", action="store_true", help="Mirror images from a local directory to the destination registry")
    
    args = parser.parse_args()

    # --- VALIDATION ---
    if not args.generate and not any([args.mirror, args.mirror_to_disk, args.disk_to_mirror]):
        parser.error("You must specify an action: --generate, --mirror, --mirror-to-disk, or --disk-to-mirror")

    if not args.images and not args.config:
        parser.error("You must provide either --images (to generate a config) or --config (to use an existing one)")

    if (args.mirror_to_disk or args.disk_to_mirror) and not args.imagedir:
        parser.error("--imagedir is required when using --mirror-to-disk or --disk-to-mirror")

    if (args.mirror or args.disk_to_mirror) and not args.dest:
        parser.error("--dest is required when using --mirror or --disk-to-mirror")

    auth_file = check_auth_file(args.authfile)

    imagedir_path = None
    if args.imagedir:
        imagedir_path = os.path.abspath(args.imagedir)
        if not os.path.exists(imagedir_path):
            print(f"Creating local directory: {imagedir_path}")
            os.makedirs(imagedir_path, exist_ok=True)

    config_path = args.generate or args.config
    is_temp_file = False
    
    if args.images:
        images = read_and_validate_images(args.images)
        if not images:
            print("No valid images found in the provided file.")
            sys.exit(1)
        print(f"Found {len(images)} images to process.")

        if not config_path and (args.mirror or args.mirror_to_disk or args.disk_to_mirror):
            temp_fd, config_path = tempfile.mkstemp(suffix='.yaml')
            os.close(temp_fd)
            is_temp_file = True

        if not args.config:
            generate_image_set_config(images, config_path, args.v2)
            if args.generate:
                print(f"Generated ImageSetConfiguration at: {config_path}")
    elif args.config:
        if not os.path.isfile(args.config):
            print(f"Error: Config file '{args.config}' not found.")
            sys.exit(1)

    if not any([args.mirror, args.mirror_to_disk, args.disk_to_mirror]):
        print("\nConfig generated successfully. Exiting.")
        sys.exit(0)

    # --- ENVIRONMENT SETUP ---
    env = os.environ.copy()
    custom_docker_config_dir = None
    
    if args.authfile:
        custom_docker_config_dir = tempfile.mkdtemp(prefix="oc-mirror-auth-")
        shutil.copyfile(auth_file, os.path.join(custom_docker_config_dir, "config.json"))
        env["DOCKER_CONFIG"] = custom_docker_config_dir

    cmd = ["oc-mirror"]

    if args.mirror:
        cmd.extend(["--config", config_path])
        if args.imagedir:
            cmd.extend(["--workspace", f"file://{imagedir_path}"])
        cmd.append(f"docker://{args.dest}")
    elif args.mirror_to_disk:
        cmd.extend(["--config", config_path])
        cmd.append(f"file://{imagedir_path}")
    elif args.disk_to_mirror:
        # Phase 2 REQUIRES the config file to be passed
        cmd.extend(["--config", config_path])
        cmd.extend(["--from", f"file://{imagedir_path}"])
        cmd.append(f"docker://{args.dest}")

    if args.v2:
        cmd.append("--v2")
        
    if args.dest_tls_verify == 'false':
        # FIXED FLAG FOR v2
        cmd.append("--dest-tls-verify=false")

    print("------------------------------------------------------")
    print(f"Mode: {'DRY RUN' if args.dry_run else 'EXECUTION'}")
    print(f"Command: {' '.join(cmd)}")
    print("------------------------------------------------------")

    if args.dry_run:
        print("Dry run requested. Exiting without launching oc-mirror.")
        if is_temp_file and os.path.exists(config_path):
            os.remove(config_path)
        if custom_docker_config_dir and os.path.exists(custom_docker_config_dir):
            shutil.rmtree(custom_docker_config_dir)
    else:
        print("Starting oc-mirror process...\n")
        try:
            subprocess.run(cmd, env=env, check=True)
            print("\nMirroring complete!")
        except subprocess.CalledProcessError as e:
            print(f"\nError: oc-mirror failed with exit code {e.returncode}")
            sys.exit(e.returncode)
        finally:
            if is_temp_file and os.path.exists(config_path):
                os.remove(config_path)
            if custom_docker_config_dir and os.path.exists(custom_docker_config_dir):
                shutil.rmtree(custom_docker_config_dir)

if __name__ == "__main__":
    main()
