#!/usr/bin/env python3
"""
NGINX CIS Benchmark Automation Tool

A comprehensive tool for automating NGINX installation, configuration,
and CIS Benchmark compliance checking across multiple Ubuntu hosts via SSH.
"""

import sys
import argparse
import logging
from datetime import datetime
from typing import List

from src.models import HostConfig, HostResult, ReportData, CheckStatus
from src.utils import load_yaml_config, setup_logging, ensure_directory
from src.ssh_manager import SSHManager
from src.nginx_installer import NGINXInstaller
from src.nginx_configurator import NGINXConfigurator
from src.benchmark_checker import BenchmarkChecker
from src.report_generator import ReportGenerator


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="NGINX CIS Benchmark Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Configure NGINX on all hosts
  python main.py --configure --hosts config/hosts.yaml
  
  # Check CIS Benchmark compliance
  python main.py --check --hosts config/hosts.yaml
  
  # Configure and check
  python main.py --configure --check --hosts config/hosts.yaml
  
  # Verbose output with custom report directory
  python main.py --check --hosts config/hosts.yaml --output ./reports --verbose
        """
    )
    
    parser.add_argument(
        "--configure",
        action="store_true",
        help="Configure NGINX according to CIS Benchmark recommendations"
    )
    
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check NGINX configuration against CIS Benchmark"
    )
    
    parser.add_argument(
        "--hosts",
        type=str,
        default="config/hosts.yaml",
        help="Path to hosts configuration file (default: config/hosts.yaml)"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default="reports",
        help="Directory for report output (default: reports/)"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip confirmation prompts (auto-confirm)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.configure and not args.check:
        parser.error("At least one of --configure or --check must be specified")
    
    return args


def process_host_configure(host_config: HostConfig, logger: logging.Logger) -> bool:
    """
    Configure NGINX on a single host.
    
    Args:
        host_config: Host configuration
        logger: Logger instance
        
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info(f"Configuring {host_config.hostname} ({host_config.ip})")
        
        with SSHManager(host_config) as ssh:
            # Install NGINX
            installer = NGINXInstaller(ssh)
            installer.install(from_official_repo=True)
            installer.start_service()
            
            # Configure NGINX
            configurator = NGINXConfigurator(ssh)
            configurator.configure(server_name=host_config.hostname)
            
            logger.info(f"Successfully configured {host_config.hostname}")
            return True
            
    except Exception as e:
        logger.error(f"Failed to configure {host_config.hostname}: {e}")
        return False


def process_host_check(host_config: HostConfig, logger: logging.Logger) -> HostResult:
    """
    Check CIS Benchmark compliance on a single host.
    
    Args:
        host_config: Host configuration
        logger: Logger instance
        
    Returns:
        HostResult with check results
    """
    try:
        logger.info(f"Checking {host_config.hostname} ({host_config.ip})")
        
        with SSHManager(host_config) as ssh:
            # Run benchmark checks
            checker = BenchmarkChecker(ssh)
            check_results = checker.run_all_checks()
            
            logger.info(f"Completed {len(check_results)} checks on {host_config.hostname}")
            
            return HostResult(
                hostname=host_config.hostname,
                ip=host_config.ip,
                status="success",
                checks=check_results
            )
            
    except Exception as e:
        logger.error(f"Failed to check {host_config.hostname}: {e}")
        return HostResult(
            hostname=host_config.hostname,
            ip=host_config.ip,
            status="failed",
            error_message=str(e)
        )


def confirm_action(action: str, hosts: List[HostConfig]) -> bool:
    """
    Ask user for confirmation before performing action.
    
    Args:
        action: Action to be performed (e.g., "configure", "check")
        hosts: List of hosts that will be affected
        
    Returns:
        True if user confirms, False otherwise
    """
    print("\n" + "="*80)
    print(f"⚠️  CONFIRMATION REQUIRED")
    print("="*80)
    print(f"\nYou are about to {action.upper()} NGINX on the following host(s):")
    print()
    
    for idx, host in enumerate(hosts, 1):
        print(f"  {idx}. {host.hostname}")
        print(f"     - IP: {host.ip}")
        print(f"     - User: {host.username}")
        print()
    
    if action == "configure":
        print("This will:")
        print("  • Install NGINX from official repository")
        print("  • Create dedicated nginx user")
        print("  • Generate SSL certificates")
        print("  • Configure NGINX according to CIS Benchmark")
        print("  • Modify NGINX configuration files")
        print("  • Restart NGINX service")
        print()
        print("⚠️  WARNING: Existing NGINX configuration will be backed up and replaced!")
    
    print("\n" + "-"*80)
    
    while True:
        try:
            response = input(f"Do you want to proceed with {action}? [y/N]: ").strip().lower()
            if response in ['y', 'yes']:
                print()
                return True
            elif response in ['n', 'no', '']:
                print("\nOperation cancelled by user.")
                return False
            else:
                print("Please enter 'y' for yes or 'n' for no.")
        except (EOFError, KeyboardInterrupt):
            print("\n\nOperation cancelled by user.")
            return False


def main():
    """Main entry point."""
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(verbose=args.verbose)
    
    # Print banner
    print("="*80)
    print("NGINX CIS Benchmark Automation Tool v1.0.0")
    print("="*80)
    print()
    
    try:
        # Ensure output directory exists
        ensure_directory(args.output)
        
        # Load host configurations
        logger.info(f"Loading host configurations from {args.hosts}")
        try:
            hosts = load_yaml_config(args.hosts)
            logger.info(f"Loaded {len(hosts)} host(s)")
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {args.hosts}")
            logger.info("Please create a configuration file. Example:")
            logger.info("  cp config/hosts.yaml.example config/hosts.yaml")
            logger.info("  # Edit config/hosts.yaml with your host information")
            sys.exit(1)
        except ValueError as e:
            logger.error(f"Invalid configuration: {e}")
            sys.exit(1)
        
        # Display configuration summary
        print(f"Mode: ", end="")
        modes = []
        if args.configure:
            modes.append("Configure")
        if args.check:
            modes.append("Check")
        print(" + ".join(modes))
        print(f"Hosts: {len(hosts)}")
        for host in hosts:
            print(f"  - {host.hostname} ({host.ip})")
        print()
        
        # Ask for confirmation before configuration
        if args.configure:
            # Skip confirmation if --yes flag is provided
            if not args.yes and not confirm_action("configure", hosts):
                sys.exit(0)
        
        # Process each host - Configuration phase
        if args.configure:
            logger.info("="*60)
            logger.info("CONFIGURATION PHASE")
            logger.info("="*60)
            
            configure_success = 0
            configure_failed = 0
            
            for host in hosts:
                success = process_host_configure(host, logger)
                if success:
                    configure_success += 1
                else:
                    configure_failed += 1
            
            logger.info(f"\nConfiguration Summary:")
            logger.info(f"  Successful: {configure_success}/{len(hosts)}")
            logger.info(f"  Failed: {configure_failed}/{len(hosts)}")
            print()
        
        # Process each host - Check phase
        if args.check:
            logger.info("="*60)
            logger.info("BENCHMARK CHECK PHASE")
            logger.info("="*60)
            
            host_results: List[HostResult] = []
            
            for host in hosts:
                result = process_host_check(host, logger)
                host_results.append(result)
            
            # Generate report
            logger.info("\nGenerating report...")
            
            report_data = ReportData(
                timestamp=datetime.now().isoformat(),
                hosts=host_results
            )
            
            # Create report generator
            report_gen = ReportGenerator(output_dir=args.output)
            
            # Save JSON report
            report_path = report_gen.save_report(report_data)
            logger.info(f"Report saved to: {report_path}")
            
            # Print summary to console
            report_gen.print_summary(report_data)
            
            # Determine exit code based on results
            summary = report_data.get_summary()
            
            if summary['failed_hosts'] > 0:
                logger.warning(f"{summary['failed_hosts']} host(s) failed to complete checks")
            
            if summary['failed'] > 0:
                logger.warning(f"{summary['failed']} check(s) failed across all hosts")
                sys.exit(2)  # Exit code 2 indicates checks failed
        
        logger.info("\nCompleted successfully!")
        sys.exit(0)
        
    except KeyboardInterrupt:
        logger.warning("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()

