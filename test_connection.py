#!/usr/bin/env python3
"""
Test SSH Connection

Simple script to test SSH connectivity to hosts before running the main tool.
"""

import sys
import argparse
from src.utils import load_yaml_config, setup_logging
from src.ssh_manager import SSHManager


def test_host_connection(host_config):
    """Test connection to a single host."""
    print(f"\n{'='*60}")
    print(f"Testing: {host_config.hostname} ({host_config.ip})")
    print(f"{'='*60}")
    
    try:
        print("Attempting to connect...")
        with SSHManager(host_config) as ssh:
            print("✓ Successfully connected!")
            
            # Test basic command
            print("\nTesting command execution...")
            stdout, stderr, exit_code = ssh.execute_command("whoami")
            print(f"✓ Command executed: whoami")
            print(f"  Result: {stdout.strip()}")
            
            # Test sudo
            print("\nTesting sudo access...")
            stdout, stderr, exit_code = ssh.execute_command("whoami", sudo=True)
            if exit_code == 0:
                print(f"✓ Sudo access confirmed: {stdout.strip()}")
            else:
                print(f"✗ Sudo access failed: {stderr.strip()}")
                return False
            
            # Check for NGINX
            print("\nChecking for NGINX...")
            stdout, stderr, exit_code = ssh.execute_command("which nginx")
            if exit_code == 0:
                # Get version
                stdout, stderr, exit_code = ssh.execute_command("nginx -v 2>&1")
                print(f"✓ NGINX found: {stdout.strip()}")
            else:
                print("  NGINX not installed (will be installed during configuration)")
            
            print("\n✓ All connection tests passed!")
            return True
            
    except Exception as e:
        print(f"\n✗ Connection failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Test SSH connectivity to hosts"
    )
    parser.add_argument(
        "--hosts",
        type=str,
        default="config/hosts.yaml",
        help="Path to hosts configuration file"
    )
    args = parser.parse_args()
    
    print("="*60)
    print("SSH Connection Test Tool")
    print("="*60)
    
    try:
        # Load hosts
        print(f"\nLoading hosts from {args.hosts}...")
        hosts = load_yaml_config(args.hosts)
        print(f"Found {len(hosts)} host(s)")
        
        # Test each host
        results = {}
        for host in hosts:
            success = test_host_connection(host)
            results[host.hostname] = success
        
        # Summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        
        successful = sum(1 for v in results.values() if v)
        failed = len(results) - successful
        
        for hostname, success in results.items():
            status = "✓ PASS" if success else "✗ FAIL"
            print(f"{status} - {hostname}")
        
        print(f"\nTotal: {len(results)} | Successful: {successful} | Failed: {failed}")
        
        if failed > 0:
            print("\nSome hosts failed connection tests.")
            print("Please verify credentials and network connectivity.")
            sys.exit(1)
        else:
            print("\nAll hosts passed connection tests!")
            print("You can now run: python main.py --configure --check")
            sys.exit(0)
            
    except FileNotFoundError:
        print(f"\n✗ Configuration file not found: {args.hosts}")
        print("\nCreate a configuration file:")
        print("  cp config/hosts.yaml.example config/hosts.yaml")
        print("  # Edit config/hosts.yaml with your host information")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

