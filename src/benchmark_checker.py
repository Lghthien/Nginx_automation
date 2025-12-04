"""CIS Benchmark Checker for NGINX."""

import re
import logging
from typing import List

from src.ssh_manager import SSHManager
from src.models import BenchmarkResult, CheckStatus


class BenchmarkChecker:
    """Check NGINX configuration against CIS Benchmark recommendations."""
    
    def __init__(self, ssh_manager: SSHManager):
        """
        Initialize Benchmark Checker.
        
        Args:
            ssh_manager: SSHManager instance for remote operations
        """
        self.ssh = ssh_manager
        self.logger = logging.getLogger("nginx_cis.checker")
    
    def run_all_checks(self) -> List[BenchmarkResult]:
        """
        Run all CIS Benchmark checks.
        
        Returns:
            List of BenchmarkResult objects
        """
        self.logger.info("Running all CIS Benchmark checks")
        
        results = []
        
        # 1. Planning and Installation
        results.append(self.check_1_1_1_nginx_installed())
        results.append(self.check_1_2_1_repo_configured())
        results.append(self.check_1_2_2_latest_version())
        
        # 2. Basic Configuration
        results.append(self.check_2_1_4_autoindex_disabled())
        results.append(self.check_2_2_1_dedicated_user())
        results.append(self.check_2_2_2_account_locked())
        results.append(self.check_2_2_3_invalid_shell())
        results.append(self.check_2_3_1_ownership())
        results.append(self.check_2_3_2_permissions())
        results.append(self.check_2_3_3_pid_secured())
        results.append(self.check_2_3_4_core_dump_secured())
        results.append(self.check_2_4_1_authorized_ports())
        results.append(self.check_2_4_2_reject_unknown_hosts())
        results.append(self.check_2_4_3_keepalive_timeout())
        results.append(self.check_2_4_4_send_timeout())
        results.append(self.check_2_5_1_server_tokens())
        results.append(self.check_2_5_3_hidden_files())
        results.append(self.check_2_5_4_proxy_info_disclosure())
        
        # 3. Logging
        results.append(self.check_3_1_detailed_logging())
        results.append(self.check_3_2_access_logging())
        results.append(self.check_3_3_error_logging())
        results.append(self.check_3_4_log_rotation())
        results.append(self.check_3_7_proxy_source_ip())
        
        # 4. TLS/SSL Configuration
        results.append(self.check_4_1_1_https_redirect())
        results.append(self.check_4_1_3_private_key_permissions())
        results.append(self.check_4_1_4_modern_tls())
        results.append(self.check_4_1_5_weak_ciphers())
        results.append(self.check_4_1_6_dhparam())
        results.append(self.check_4_1_8_hsts())
        results.append(self.check_4_1_9_upstream_client_cert())
        results.append(self.check_4_1_12_session_resumption())
        results.append(self.check_4_1_13_http2())
        
        # 5. Request Filtering
        results.append(self.check_5_2_1_client_timeouts())
        results.append(self.check_5_2_2_max_body_size())
        results.append(self.check_5_2_3_buffer_size())
        results.append(self.check_5_3_1_x_frame_options())
        results.append(self.check_5_3_2_x_content_type_options())
        results.append(self.check_5_3_3_csp())
        
        self.logger.info(f"Completed {len(results)} CIS Benchmark checks")
        
        return results
    
    def _get_nginx_config(self) -> str:
        """Get NGINX main configuration file content."""
        try:
            return self.ssh.read_file("/etc/nginx/nginx.conf", sudo=True)
        except Exception as e:
            self.logger.error(f"Failed to read nginx.conf: {e}")
            return ""
    
    def _get_all_configs(self) -> str:
        """Get all NGINX configuration files content."""
        try:
            # Get main config
            main_config = self._get_nginx_config()
            
            # Get conf.d configs
            stdout, _, _ = self.ssh.execute_command(
                "cat /etc/nginx/conf.d/*.conf 2>/dev/null || true",
                sudo=True
            )
            conf_d = stdout
            
            # Get sites-enabled configs
            stdout, _, _ = self.ssh.execute_command(
                "cat /etc/nginx/sites-enabled/* 2>/dev/null || true",
                sudo=True
            )
            sites_enabled = stdout
            
            return main_config + "\n" + conf_d + "\n" + sites_enabled
            
        except Exception as e:
            self.logger.error(f"Failed to read configs: {e}")
            return ""
    
    # ==================== 1. Planning and Installation ====================
    
    def check_1_1_1_nginx_installed(self) -> BenchmarkResult:
        """1.1.1 Ensure NGINX is installed."""
        try:
            stdout, _, exit_code = self.ssh.execute_command("which nginx")
            
            if exit_code == 0 and stdout.strip():
                # Get version
                stdout, _, _ = self.ssh.execute_command("nginx -v 2>&1")
                version = stdout.strip() if stdout else "unknown"
                
                return BenchmarkResult(
                    check_id="1.1.1",
                    name="Ensure NGINX is installed",
                    status=CheckStatus.PASS,
                    details=f"NGINX is installed: {version}",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="1.1.1",
                    name="Ensure NGINX is installed",
                    status=CheckStatus.FAIL,
                    details="NGINX is not installed",
                    remediation="Install NGINX using the official repository"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="1.1.1",
                name="Ensure NGINX is installed",
                status=CheckStatus.ERROR,
                details=f"Error checking NGINX installation: {e}",
                remediation=""
            )
    
    def check_1_2_1_repo_configured(self) -> BenchmarkResult:
        """1.2.1 Ensure package manager repositories are properly configured."""
        try:
            # Check for NGINX official repository
            stdout, _, exit_code = self.ssh.execute_command(
                "grep -r 'nginx.org' /etc/apt/sources.list.d/ 2>/dev/null || true"
            )
            
            has_official_repo = "nginx.org" in stdout
            
            if has_official_repo:
                return BenchmarkResult(
                    check_id="1.2.1",
                    name="Ensure package manager repositories are properly configured",
                    status=CheckStatus.PASS,
                    details="NGINX official repository is configured",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="1.2.1",
                    name="Ensure package manager repositories are properly configured",
                    status=CheckStatus.WARNING,
                    details="NGINX official repository not detected (may be using distribution repository)",
                    remediation="Configure NGINX official repository for latest updates"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="1.2.1",
                name="Ensure package manager repositories are properly configured",
                status=CheckStatus.ERROR,
                details=f"Error checking repository configuration: {e}",
                remediation=""
            )
    
    def check_1_2_2_latest_version(self) -> BenchmarkResult:
        """1.2.2 Ensure the latest software package is installed."""
        try:
            # Get current version
            stdout, _, _ = self.ssh.execute_command("nginx -v 2>&1")
            current_version = stdout.strip()
            
            # Check for updates
            stdout, _, _ = self.ssh.execute_command(
                "apt-get update > /dev/null 2>&1 && apt list --upgradable 2>/dev/null | grep nginx || true",
                sudo=True
            )
            
            if "nginx" in stdout.lower() and "upgradable" in stdout.lower():
                return BenchmarkResult(
                    check_id="1.2.2",
                    name="Ensure the latest software package is installed",
                    status=CheckStatus.WARNING,
                    details=f"Current: {current_version}. Updates available.",
                    remediation="Update NGINX to the latest version: apt-get update && apt-get upgrade nginx"
                )
            else:
                return BenchmarkResult(
                    check_id="1.2.2",
                    name="Ensure the latest software package is installed",
                    status=CheckStatus.PASS,
                    details=f"NGINX is up to date: {current_version}",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="1.2.2",
                name="Ensure the latest software package is installed",
                status=CheckStatus.ERROR,
                details=f"Error checking version: {e}",
                remediation=""
            )
    
    # ==================== 2. Basic Configuration ====================
    
    def check_2_1_4_autoindex_disabled(self) -> BenchmarkResult:
        """2.1.4 Ensure the autoindex module is disabled."""
        try:
            config = self._get_all_configs()
            
            # Check for autoindex on
            if re.search(r'autoindex\s+on', config):
                return BenchmarkResult(
                    check_id="2.1.4",
                    name="Ensure the autoindex module is disabled",
                    status=CheckStatus.FAIL,
                    details="autoindex is enabled in configuration",
                    remediation="Set 'autoindex off;' in NGINX configuration"
                )
            else:
                return BenchmarkResult(
                    check_id="2.1.4",
                    name="Ensure the autoindex module is disabled",
                    status=CheckStatus.PASS,
                    details="autoindex is disabled (off or not configured)",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.1.4",
                name="Ensure the autoindex module is disabled",
                status=CheckStatus.ERROR,
                details=f"Error checking autoindex: {e}",
                remediation=""
            )
    
    def check_2_2_1_dedicated_user(self) -> BenchmarkResult:
        """2.2.1 Ensure NGINX is run using a non-privileged, dedicated service account."""
        try:
            config = self._get_nginx_config()
            
            # Extract user directive
            match = re.search(r'user\s+(\w+)', config)
            
            if match:
                user = match.group(1)
                if user != "root":
                    return BenchmarkResult(
                        check_id="2.2.1",
                        name="Ensure NGINX is run using a non-privileged, dedicated service account",
                        status=CheckStatus.PASS,
                        details=f"NGINX runs as non-root user: {user}",
                        remediation=""
                    )
                else:
                    return BenchmarkResult(
                        check_id="2.2.1",
                        name="Ensure NGINX is run using a non-privileged, dedicated service account",
                        status=CheckStatus.FAIL,
                        details="NGINX is configured to run as root",
                        remediation="Configure NGINX to run as non-root user (e.g., 'user nginx;')"
                    )
            else:
                return BenchmarkResult(
                    check_id="2.2.1",
                    name="Ensure NGINX is run using a non-privileged, dedicated service account",
                    status=CheckStatus.WARNING,
                    details="User directive not found in configuration",
                    remediation="Add 'user nginx;' directive to nginx.conf"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.2.1",
                name="Ensure NGINX is run using a non-privileged, dedicated service account",
                status=CheckStatus.ERROR,
                details=f"Error checking user configuration: {e}",
                remediation=""
            )
    
    def check_2_2_2_account_locked(self) -> BenchmarkResult:
        """2.2.2 Ensure the NGINX service account is locked."""
        try:
            # Get nginx user from config
            config = self._get_nginx_config()
            match = re.search(r'user\s+(\w+)', config)
            user = match.group(1) if match else "nginx"
            
            # Check if account is locked
            stdout, _, exit_code = self.ssh.execute_command(
                f"passwd -S {user} 2>/dev/null || true",
                sudo=True
            )
            
            if "L" in stdout or "locked" in stdout.lower():
                return BenchmarkResult(
                    check_id="2.2.2",
                    name="Ensure the NGINX service account is locked",
                    status=CheckStatus.PASS,
                    details=f"Account {user} is locked",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="2.2.2",
                    name="Ensure the NGINX service account is locked",
                    status=CheckStatus.FAIL,
                    details=f"Account {user} is not locked",
                    remediation=f"Lock the account: passwd -l {user}"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.2.2",
                name="Ensure the NGINX service account is locked",
                status=CheckStatus.ERROR,
                details=f"Error checking account lock status: {e}",
                remediation=""
            )
    
    def check_2_2_3_invalid_shell(self) -> BenchmarkResult:
        """2.2.3 Ensure the NGINX service account has an invalid shell."""
        try:
            # Get nginx user from config
            config = self._get_nginx_config()
            match = re.search(r'user\s+(\w+)', config)
            user = match.group(1) if match else "nginx"
            
            # Check user's shell
            stdout, _, exit_code = self.ssh.execute_command(
                f"getent passwd {user} | cut -d: -f7"
            )
            
            shell = stdout.strip()
            invalid_shells = ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"]
            
            if shell in invalid_shells:
                return BenchmarkResult(
                    check_id="2.2.3",
                    name="Ensure the NGINX service account has an invalid shell",
                    status=CheckStatus.PASS,
                    details=f"User {user} has invalid shell: {shell}",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="2.2.3",
                    name="Ensure the NGINX service account has an invalid shell",
                    status=CheckStatus.FAIL,
                    details=f"User {user} has valid shell: {shell}",
                    remediation=f"Set invalid shell: usermod -s /usr/sbin/nologin {user}"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.2.3",
                name="Ensure the NGINX service account has an invalid shell",
                status=CheckStatus.ERROR,
                details=f"Error checking shell: {e}",
                remediation=""
            )
    
    def check_2_3_1_ownership(self) -> BenchmarkResult:
        """2.3.1 Ensure NGINX directories and files are owned by root."""
        try:
            # Check ownership of /etc/nginx
            stdout, _, exit_code = self.ssh.execute_command(
                "find /etc/nginx -not -user root -o -not -group root 2>/dev/null | head -10",
                sudo=True
            )
            
            if stdout.strip():
                return BenchmarkResult(
                    check_id="2.3.1",
                    name="Ensure NGINX directories and files are owned by root",
                    status=CheckStatus.FAIL,
                    details=f"Found files not owned by root: {stdout.strip()[:200]}",
                    remediation="Set ownership: chown -R root:root /etc/nginx"
                )
            else:
                return BenchmarkResult(
                    check_id="2.3.1",
                    name="Ensure NGINX directories and files are owned by root",
                    status=CheckStatus.PASS,
                    details="All NGINX files are owned by root",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.3.1",
                name="Ensure NGINX directories and files are owned by root",
                status=CheckStatus.ERROR,
                details=f"Error checking ownership: {e}",
                remediation=""
            )
    
    def check_2_3_2_permissions(self) -> BenchmarkResult:
        """2.3.2 Ensure access to NGINX directories and files is restricted."""
        try:
            # Check for overly permissive files
            stdout, _, exit_code = self.ssh.execute_command(
                "find /etc/nginx -type f -perm /o+w 2>/dev/null | head -10",
                sudo=True
            )
            
            if stdout.strip():
                return BenchmarkResult(
                    check_id="2.3.2",
                    name="Ensure access to NGINX directories and files is restricted",
                    status=CheckStatus.FAIL,
                    details=f"Found world-writable files: {stdout.strip()[:200]}",
                    remediation="Remove world-write: chmod -R o-w /etc/nginx"
                )
            else:
                return BenchmarkResult(
                    check_id="2.3.2",
                    name="Ensure access to NGINX directories and files is restricted",
                    status=CheckStatus.PASS,
                    details="File permissions are properly restricted",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.3.2",
                name="Ensure access to NGINX directories and files is restricted",
                status=CheckStatus.ERROR,
                details=f"Error checking permissions: {e}",
                remediation=""
            )
    
    def check_2_3_3_pid_secured(self) -> BenchmarkResult:
        """2.3.3 Ensure the NGINX process ID (PID) file is secured."""
        try:
            # Find PID file location
            config = self._get_nginx_config()
            match = re.search(r'pid\s+([^;]+);', config)
            pid_file = match.group(1).strip() if match else "/var/run/nginx.pid"
            
            # Check if file exists and permissions
            stdout, _, exit_code = self.ssh.execute_command(
                f"ls -l {pid_file} 2>/dev/null || echo 'not_found'",
                sudo=True
            )
            
            if "not_found" in stdout:
                return BenchmarkResult(
                    check_id="2.3.3",
                    name="Ensure the NGINX process ID (PID) file is secured",
                    status=CheckStatus.WARNING,
                    details=f"PID file not found: {pid_file}",
                    remediation="Start NGINX service to create PID file"
                )
            
            # Check permissions (should be 644 or more restrictive)
            if re.search(r'-rw-r--r--', stdout) or re.search(r'-rw-------', stdout):
                return BenchmarkResult(
                    check_id="2.3.3",
                    name="Ensure the NGINX process ID (PID) file is secured",
                    status=CheckStatus.PASS,
                    details=f"PID file has proper permissions: {pid_file}",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="2.3.3",
                    name="Ensure the NGINX process ID (PID) file is secured",
                    status=CheckStatus.FAIL,
                    details=f"PID file has improper permissions: {stdout.strip()}",
                    remediation=f"Set proper permissions: chmod 644 {pid_file}"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.3.3",
                name="Ensure the NGINX process ID (PID) file is secured",
                status=CheckStatus.ERROR,
                details=f"Error checking PID file: {e}",
                remediation=""
            )
    
    def check_2_3_4_core_dump_secured(self) -> BenchmarkResult:
        """2.3.4 Ensure the core dump directory is secured."""
        try:
            # Check for working_directory directive
            config = self._get_nginx_config()
            match = re.search(r'working_directory\s+([^;]+);', config)
            
            if not match:
                return BenchmarkResult(
                    check_id="2.3.4",
                    name="Ensure the core dump directory is secured",
                    status=CheckStatus.WARNING,
                    details="working_directory directive not found",
                    remediation="Add 'working_directory /var/lib/nginx;' to nginx.conf"
                )
            
            work_dir = match.group(1).strip()
            
            # Check directory exists
            stdout, _, exit_code = self.ssh.execute_command(
                f"ls -ld {work_dir} 2>/dev/null",
                sudo=True
            )
            
            if exit_code != 0:
                return BenchmarkResult(
                    check_id="2.3.4",
                    name="Ensure the core dump directory is secured",
                    status=CheckStatus.FAIL,
                    details=f"Working directory does not exist: {work_dir}",
                    remediation=f"Create directory: mkdir -p {work_dir} && chown nginx:root {work_dir} && chmod 750 {work_dir}"
                )
            
            # Parse permissions and ownership from ls -ld output
            # Format: drwxr-x--- 2 nginx root 4096 date time path
            parts = stdout.strip().split()
            if len(parts) < 9:
                return BenchmarkResult(
                    check_id="2.3.4",
                    name="Ensure the core dump directory is secured",
                    status=CheckStatus.ERROR,
                    details=f"Cannot parse directory info: {stdout.strip()}",
                    remediation=""
                )
            
            perms = parts[0]
            owner = parts[2]
            group = parts[3]
            
            issues = []
            
            # Check 1: Not within web document root (simple check - should not be under /var/www or /usr/share/nginx/html)
            if '/var/www' in work_dir or '/usr/share/nginx/html' in work_dir:
                issues.append(f"Directory is within web document root: {work_dir}")
            
            # Check 2: Owned by root
            if owner != 'root' and owner != 'nginx':
                issues.append(f"Owner should be root or nginx, found: {owner}")
            
            # Check 3: Group ownership should be nginx or root
            if group not in ['nginx', 'root']:
                issues.append(f"Group should be nginx or root, found: {group}")
            
            # Check 4: No read-write-execute for others (o=rwx)
            # Permission string format: drwxr-xr-x
            # Position 7-9 are 'other' permissions
            if len(perms) >= 10:
                other_perms = perms[7:10]
                if other_perms != '---':
                    issues.append(f"Other users have permissions ({other_perms}), should be no access (---)")
            
            if issues:
                return BenchmarkResult(
                    check_id="2.3.4",
                    name="Ensure the core dump directory is secured",
                    status=CheckStatus.FAIL,
                    details=f"Security issues found: {'; '.join(issues)}",
                    remediation=f"Fix with: chown nginx:root {work_dir} && chmod 750 {work_dir}"
                )
            else:
                return BenchmarkResult(
                    check_id="2.3.4",
                    name="Ensure the core dump directory is secured",
                    status=CheckStatus.PASS,
                    details=f"Core dump directory is properly secured: {work_dir} ({owner}:{group} {perms})",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.3.4",
                name="Ensure the core dump directory is secured",
                status=CheckStatus.ERROR,
                details=f"Error checking core dump directory: {e}",
                remediation=""
            )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.3.4",
                name="Ensure the core dump directory is secured",
                status=CheckStatus.ERROR,
                details=f"Error checking core dump directory: {e}",
                remediation=""
            )
    
    def check_2_4_1_authorized_ports(self) -> BenchmarkResult:
        """2.4.1 Ensure NGINX only listens for network connections on authorized ports."""
        try:
            config = self._get_all_configs()
            
            # Find all listen directives
            listen_matches = re.findall(r'listen\s+(?:\[::\]:)?(\d+)', config)
            
            if not listen_matches:
                return BenchmarkResult(
                    check_id="2.4.1",
                    name="Ensure NGINX only listens on authorized ports",
                    status=CheckStatus.WARNING,
                    details="No listen directives found",
                    remediation="Configure listen directives for ports 80 and 443"
                )
            
            ports = set(listen_matches)
            authorized_ports = {'80', '443'}
            unauthorized = ports - authorized_ports
            
            details = f"Listening on ports: {', '.join(sorted(ports))}"
            
            if unauthorized:
                return BenchmarkResult(
                    check_id="2.4.1",
                    name="Ensure NGINX only listens on authorized ports",
                    status=CheckStatus.WARNING,
                    details=f"{details}. Unauthorized ports: {', '.join(sorted(unauthorized))}",
                    remediation="Review and remove unauthorized listen directives"
                )
            else:
                return BenchmarkResult(
                    check_id="2.4.1",
                    name="Ensure NGINX only listens on authorized ports",
                    status=CheckStatus.PASS,
                    details=details,
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.4.1",
                name="Ensure NGINX only listens on authorized ports",
                status=CheckStatus.ERROR,
                details=f"Error checking listen ports: {e}",
                remediation=""
            )
    
    def check_2_4_2_reject_unknown_hosts(self) -> BenchmarkResult:
        """2.4.2 Ensure requests for unknown host names are rejected."""
        try:
            config = self._get_all_configs()
            
            # Look for default_server with return 444
            has_default_reject = re.search(
                r'server\s*\{[^}]*default_server[^}]*return\s+444',
                config,
                re.DOTALL
            )
            
            if has_default_reject:
                return BenchmarkResult(
                    check_id="2.4.2",
                    name="Ensure requests for unknown host names are rejected",
                    status=CheckStatus.PASS,
                    details="Default server configured to reject unknown hosts (return 444)",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="2.4.2",
                    name="Ensure requests for unknown host names are rejected",
                    status=CheckStatus.FAIL,
                    details="No default server configured to reject unknown hosts",
                    remediation="Add default_server block with 'return 444;'"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.4.2",
                name="Ensure requests for unknown host names are rejected",
                status=CheckStatus.ERROR,
                details=f"Error checking default server: {e}",
                remediation=""
            )
    
    def check_2_4_3_keepalive_timeout(self) -> BenchmarkResult:
        """2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0."""
        try:
            config = self._get_all_configs()
            
            # Find keepalive_timeout directives
            matches = re.findall(r'keepalive_timeout\s+(\d+)', config)
            
            if not matches:
                return BenchmarkResult(
                    check_id="2.4.3",
                    name="Ensure keepalive_timeout is 10 seconds or less",
                    status=CheckStatus.WARNING,
                    details="keepalive_timeout not explicitly configured (using default)",
                    remediation="Set 'keepalive_timeout 10;' in configuration"
                )
            
            # Check all values
            invalid = []
            for timeout in matches:
                timeout_val = int(timeout)
                if timeout_val == 0 or timeout_val > 10:
                    invalid.append(timeout_val)
            
            if invalid:
                return BenchmarkResult(
                    check_id="2.4.3",
                    name="Ensure keepalive_timeout is 10 seconds or less",
                    status=CheckStatus.FAIL,
                    details=f"Invalid keepalive_timeout values found: {invalid}",
                    remediation="Set keepalive_timeout between 1 and 10 seconds"
                )
            else:
                return BenchmarkResult(
                    check_id="2.4.3",
                    name="Ensure keepalive_timeout is 10 seconds or less",
                    status=CheckStatus.PASS,
                    details=f"keepalive_timeout properly configured: {matches[0]}s",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.4.3",
                name="Ensure keepalive_timeout is 10 seconds or less",
                status=CheckStatus.ERROR,
                details=f"Error checking keepalive_timeout: {e}",
                remediation=""
            )
    
    def check_2_4_4_send_timeout(self) -> BenchmarkResult:
        """2.4.4 Ensure send_timeout is set to 10 seconds or less, but not 0."""
        try:
            config = self._get_all_configs()
            
            # Find send_timeout directives
            matches = re.findall(r'send_timeout\s+(\d+)', config)
            
            if not matches:
                return BenchmarkResult(
                    check_id="2.4.4",
                    name="Ensure send_timeout is 10 seconds or less",
                    status=CheckStatus.WARNING,
                    details="send_timeout not explicitly configured (using default 60s)",
                    remediation="Set 'send_timeout 10;' in configuration"
                )
            
            # Check all values
            invalid = []
            for timeout in matches:
                timeout_val = int(timeout)
                if timeout_val == 0 or timeout_val > 10:
                    invalid.append(timeout_val)
            
            if invalid:
                return BenchmarkResult(
                    check_id="2.4.4",
                    name="Ensure send_timeout is 10 seconds or less",
                    status=CheckStatus.FAIL,
                    details=f"Invalid send_timeout values found: {invalid}",
                    remediation="Set send_timeout between 1 and 10 seconds"
                )
            else:
                return BenchmarkResult(
                    check_id="2.4.4",
                    name="Ensure send_timeout is 10 seconds or less",
                    status=CheckStatus.PASS,
                    details=f"send_timeout properly configured: {matches[0]}s",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.4.4",
                name="Ensure send_timeout is 10 seconds or less",
                status=CheckStatus.ERROR,
                details=f"Error checking send_timeout: {e}",
                remediation=""
            )
    
    def check_2_5_1_server_tokens(self) -> BenchmarkResult:
        """2.5.1 Ensure server_tokens directive is set to `off`."""
        try:
            config = self._get_all_configs()
            
            # Check for server_tokens off
            if re.search(r'server_tokens\s+off', config):
                return BenchmarkResult(
                    check_id="2.5.1",
                    name="Ensure server_tokens directive is set to `off`",
                    status=CheckStatus.PASS,
                    details="server_tokens is set to off",
                    remediation=""
                )
            elif re.search(r'server_tokens\s+on', config):
                return BenchmarkResult(
                    check_id="2.5.1",
                    name="Ensure server_tokens directive is set to `off`",
                    status=CheckStatus.FAIL,
                    details="server_tokens is explicitly set to on",
                    remediation="Set 'server_tokens off;' in configuration"
                )
            else:
                return BenchmarkResult(
                    check_id="2.5.1",
                    name="Ensure server_tokens directive is set to `off`",
                    status=CheckStatus.WARNING,
                    details="server_tokens not configured (default is on)",
                    remediation="Set 'server_tokens off;' in configuration"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.5.1",
                name="Ensure server_tokens directive is set to `off`",
                status=CheckStatus.ERROR,
                details=f"Error checking server_tokens: {e}",
                remediation=""
            )
    
    def check_2_5_3_hidden_files(self) -> BenchmarkResult:
        """2.5.3 Ensure hidden file serving is disabled."""
        try:
            config = self._get_all_configs()
            
            # Check for location block denying hidden files
            has_hidden_deny = re.search(r'location\s+~\s+[\'"]?/\\.', config)
            
            if has_hidden_deny and re.search(r'deny\s+all', config):
                return BenchmarkResult(
                    check_id="2.5.3",
                    name="Ensure hidden file serving is disabled",
                    status=CheckStatus.PASS,
                    details="Hidden files are blocked",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="2.5.3",
                    name="Ensure hidden file serving is disabled",
                    status=CheckStatus.FAIL,
                    details="No location block found to deny hidden files",
                    remediation="Add location block: location ~ /\\. { deny all; }"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.5.3",
                name="Ensure hidden file serving is disabled",
                status=CheckStatus.ERROR,
                details=f"Error checking hidden files: {e}",
                remediation=""
            )
    
    def check_2_5_4_proxy_info_disclosure(self) -> BenchmarkResult:
        """2.5.4 Ensure the NGINX reverse proxy does not enable information disclosure."""
        try:
            config = self._get_all_configs()
            
            # Check if there are proxy configurations
            has_proxy = re.search(r'proxy_pass\s+', config)
            
            if not has_proxy:
                return BenchmarkResult(
                    check_id="2.5.4",
                    name="Ensure reverse proxy does not enable information disclosure",
                    status=CheckStatus.NOT_APPLICABLE,
                    details="No proxy configuration found",
                    remediation=""
                )
            
            # Check for proxy_hide_header directives
            hides_powered_by = re.search(r'proxy_hide_header\s+X-Powered-By', config)
            hides_server = re.search(r'proxy_hide_header\s+Server', config)
            
            if hides_powered_by and hides_server:
                return BenchmarkResult(
                    check_id="2.5.4",
                    name="Ensure reverse proxy does not enable information disclosure",
                    status=CheckStatus.PASS,
                    details="Proxy hides information disclosure headers",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="2.5.4",
                    name="Ensure reverse proxy does not enable information disclosure",
                    status=CheckStatus.WARNING,
                    details="Proxy may expose information headers",
                    remediation="Add proxy_hide_header directives for X-Powered-By and Server"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="2.5.4",
                name="Ensure reverse proxy does not enable information disclosure",
                status=CheckStatus.ERROR,
                details=f"Error checking proxy configuration: {e}",
                remediation=""
            )
    
    # ==================== 3. Logging ====================
    
    def check_3_1_detailed_logging(self) -> BenchmarkResult:
        """3.1 Ensure detailed logging is enabled."""
        try:
            config = self._get_all_configs()
            
            # Check for custom log_format with detailed information
            has_detailed_format = re.search(
                r'log_format.*\$remote_addr.*\$request.*\$status',
                config,
                re.DOTALL
            )
            
            if has_detailed_format:
                return BenchmarkResult(
                    check_id="3.1",
                    name="Ensure detailed logging is enabled",
                    status=CheckStatus.PASS,
                    details="Detailed log format is configured",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="3.1",
                    name="Ensure detailed logging is enabled",
                    status=CheckStatus.WARNING,
                    details="Custom detailed log format not found (using default)",
                    remediation="Configure custom log_format with detailed fields"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="3.1",
                name="Ensure detailed logging is enabled",
                status=CheckStatus.ERROR,
                details=f"Error checking logging configuration: {e}",
                remediation=""
            )
    
    def check_3_2_access_logging(self) -> BenchmarkResult:
        """3.2 Ensure access logging is enabled."""
        try:
            config = self._get_all_configs()
            
            # Check for access_log directives
            access_logs = re.findall(r'access_log\s+([^;]+);', config)
            
            # Check for access_log off (in any location or server block)
            has_disabled = re.search(r'access_log\s+off', config)
            
            if has_disabled:
                # Check if there are also enabled logs (could be disabled in specific locations)
                enabled_logs = [log for log in access_logs if 'off' not in log.lower()]
                if enabled_logs:
                    return BenchmarkResult(
                        check_id="3.2",
                        name="Ensure access logging is enabled",
                        status=CheckStatus.PASS,
                        details=f"Access logging is enabled globally: {', '.join([log.split()[0] for log in enabled_logs[:2]])}",
                        remediation=""
                    )
                else:
                    return BenchmarkResult(
                        check_id="3.2",
                        name="Ensure access logging is enabled",
                        status=CheckStatus.FAIL,
                        details="Access logging is explicitly disabled",
                        remediation="Enable access logging by removing 'access_log off;' or adding 'access_log /var/log/nginx/access.log;'"
                    )
            elif access_logs:
                log_files = [log.split()[0] for log in access_logs if 'off' not in log.lower()]
                if log_files:
                    return BenchmarkResult(
                        check_id="3.2",
                        name="Ensure access logging is enabled",
                        status=CheckStatus.PASS,
                        details=f"Access logging is enabled: {', '.join(log_files[:3])}",
                        remediation=""
                    )
                else:
                    return BenchmarkResult(
                        check_id="3.2",
                        name="Ensure access logging is enabled",
                        status=CheckStatus.FAIL,
                        details="All access_log directives are set to 'off'",
                        remediation="Enable access logging: access_log /var/log/nginx/access.log main;"
                    )
            else:
                return BenchmarkResult(
                    check_id="3.2",
                    name="Ensure access logging is enabled",
                    status=CheckStatus.PASS,
                    details="Access logging enabled (using default)",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="3.2",
                name="Ensure access logging is enabled",
                status=CheckStatus.ERROR,
                details=f"Error checking access logging: {e}",
                remediation=""
            )
    
    def check_3_3_error_logging(self) -> BenchmarkResult:
        """3.3 Ensure error logging is enabled and set to the info logging level."""
        try:
            config = self._get_nginx_config()
            
            # Find error_log directives
            error_logs = re.findall(r'error_log\s+([^;]+);', config)
            
            if not error_logs:
                return BenchmarkResult(
                    check_id="3.3",
                    name="Ensure error logging is enabled and set to info level",
                    status=CheckStatus.WARNING,
                    details="error_log not configured (using default)",
                    remediation="Configure error_log with info level"
                )
            
            # Check log level
            has_info = any('info' in log or 'warn' in log or 'error' in log for log in error_logs)
            
            if has_info:
                return BenchmarkResult(
                    check_id="3.3",
                    name="Ensure error logging is enabled and set to info level",
                    status=CheckStatus.PASS,
                    details=f"Error logging configured: {error_logs[0]}",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="3.3",
                    name="Ensure error logging is enabled and set to info level",
                    status=CheckStatus.WARNING,
                    details="Error logging level not explicitly set to info",
                    remediation="Set error_log to info level: error_log /var/log/nginx/error.log info;"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="3.3",
                name="Ensure error logging is enabled and set to info level",
                status=CheckStatus.ERROR,
                details=f"Error checking error logging: {e}",
                remediation=""
            )
    
    def check_3_4_log_rotation(self) -> BenchmarkResult:
        """3.4 Ensure log files are rotated."""
        try:
            # Check for logrotate configuration
            stdout, _, exit_code = self.ssh.execute_command(
                "test -f /etc/logrotate.d/nginx && echo 'exists' || echo 'not_found'"
            )
            
            if "exists" in stdout:
                # Read logrotate config
                content, _, _ = self.ssh.execute_command(
                    "cat /etc/logrotate.d/nginx",
                    sudo=True
                )
                
                has_rotate = "rotate" in content
                has_postrotate = "postrotate" in content or "reload" in content
                
                if has_rotate and has_postrotate:
                    return BenchmarkResult(
                        check_id="3.4",
                        name="Ensure log files are rotated",
                        status=CheckStatus.PASS,
                        details="Logrotate is configured for NGINX",
                        remediation=""
                    )
                else:
                    return BenchmarkResult(
                        check_id="3.4",
                        name="Ensure log files are rotated",
                        status=CheckStatus.WARNING,
                        details="Logrotate config exists but may be incomplete",
                        remediation="Verify logrotate configuration includes rotation and reload"
                    )
            else:
                return BenchmarkResult(
                    check_id="3.4",
                    name="Ensure log files are rotated",
                    status=CheckStatus.FAIL,
                    details="Logrotate not configured for NGINX",
                    remediation="Create /etc/logrotate.d/nginx configuration"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="3.4",
                name="Ensure log files are rotated",
                status=CheckStatus.ERROR,
                details=f"Error checking log rotation: {e}",
                remediation=""
            )
    
    def check_3_7_proxy_source_ip(self) -> BenchmarkResult:
        """3.7 Ensure proxies pass source IP information."""
        try:
            config = self._get_all_configs()
            
            # Check if there are proxy configurations
            has_proxy = re.search(r'proxy_pass\s+', config)
            
            if not has_proxy:
                return BenchmarkResult(
                    check_id="3.7",
                    name="Ensure proxies pass source IP information",
                    status=CheckStatus.NOT_APPLICABLE,
                    details="No proxy configuration found",
                    remediation=""
                )
            
            # Check for X-Forwarded-For and X-Real-IP headers
            has_xff = re.search(r'proxy_set_header\s+X-Forwarded-For', config)
            has_real_ip = re.search(r'proxy_set_header\s+X-Real-IP', config)
            
            if has_xff and has_real_ip:
                return BenchmarkResult(
                    check_id="3.7",
                    name="Ensure proxies pass source IP information",
                    status=CheckStatus.PASS,
                    details="Proxy passes source IP headers (X-Forwarded-For, X-Real-IP)",
                    remediation=""
                )
            elif has_xff or has_real_ip:
                return BenchmarkResult(
                    check_id="3.7",
                    name="Ensure proxies pass source IP information",
                    status=CheckStatus.WARNING,
                    details="Only partial source IP headers configured",
                    remediation="Add both X-Forwarded-For and X-Real-IP headers"
                )
            else:
                return BenchmarkResult(
                    check_id="3.7",
                    name="Ensure proxies pass source IP information",
                    status=CheckStatus.FAIL,
                    details="Proxy does not pass source IP information",
                    remediation="Add proxy_set_header directives for X-Forwarded-For and X-Real-IP"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="3.7",
                name="Ensure proxies pass source IP information",
                status=CheckStatus.ERROR,
                details=f"Error checking proxy headers: {e}",
                remediation=""
            )
    
    # ==================== 4. TLS/SSL Configuration ====================
    
    def check_4_1_1_https_redirect(self) -> BenchmarkResult:
        """4.1.1 Ensure HTTP is redirected to HTTPS."""
        try:
            config = self._get_all_configs()
            
            # Check for HTTP to HTTPS redirect
            has_redirect = re.search(
                r'listen\s+80[^}]*return\s+301\s+https',
                config,
                re.DOTALL
            )
            
            if has_redirect:
                return BenchmarkResult(
                    check_id="4.1.1",
                    name="Ensure HTTP is redirected to HTTPS",
                    status=CheckStatus.PASS,
                    details="HTTP to HTTPS redirect is configured",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="4.1.1",
                    name="Ensure HTTP is redirected to HTTPS",
                    status=CheckStatus.FAIL,
                    details="HTTP to HTTPS redirect not found",
                    remediation="Add 'return 301 https://$host$request_uri;' to port 80 server block"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.1",
                name="Ensure HTTP is redirected to HTTPS",
                status=CheckStatus.ERROR,
                details=f"Error checking HTTPS redirect: {e}",
                remediation=""
            )
    
    def check_4_1_3_private_key_permissions(self) -> BenchmarkResult:
        """4.1.3 Ensure private key permissions are restricted."""
        try:
            # Find SSL private keys
            stdout, _, exit_code = self.ssh.execute_command(
                "find /etc/nginx -name '*.key' 2>/dev/null",
                sudo=True
            )
            
            if not stdout.strip():
                return BenchmarkResult(
                    check_id="4.1.3",
                    name="Ensure private key permissions are restricted",
                    status=CheckStatus.WARNING,
                    details="No SSL private keys found",
                    remediation="Configure SSL certificates"
                )
            
            key_files = stdout.strip().split('\n')
            
            # Check permissions of each key
            insecure_keys = []
            for key_file in key_files:
                perm_output, _, _ = self.ssh.execute_command(
                    f"stat -c '%a %U:%G' {key_file}",
                    sudo=True
                )
                
                perms = perm_output.strip().split()[0] if perm_output else ""
                
                # Should be 400 or 600 (not readable by group/others)
                if not re.match(r'^[46]00$', perms):
                    insecure_keys.append(f"{key_file} ({perms})")
            
            if insecure_keys:
                return BenchmarkResult(
                    check_id="4.1.3",
                    name="Ensure private key permissions are restricted",
                    status=CheckStatus.FAIL,
                    details=f"Insecure key permissions: {', '.join(insecure_keys[:3])}",
                    remediation="Set proper permissions: chmod 400 /path/to/key.key"
                )
            else:
                return BenchmarkResult(
                    check_id="4.1.3",
                    name="Ensure private key permissions are restricted",
                    status=CheckStatus.PASS,
                    details=f"All private keys have proper permissions ({len(key_files)} checked)",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.3",
                name="Ensure private key permissions are restricted",
                status=CheckStatus.ERROR,
                details=f"Error checking key permissions: {e}",
                remediation=""
            )
    
    def check_4_1_4_modern_tls(self) -> BenchmarkResult:
        """4.1.4 Ensure only modern TLS protocols are used."""
        try:
            config = self._get_all_configs()
            
            # Find ssl_protocols directives
            ssl_protocols = re.findall(r'ssl_protocols\s+([^;]+);', config)
            
            if not ssl_protocols:
                return BenchmarkResult(
                    check_id="4.1.4",
                    name="Ensure only modern TLS protocols are used",
                    status=CheckStatus.WARNING,
                    details="ssl_protocols not explicitly configured",
                    remediation="Set 'ssl_protocols TLSv1.2 TLSv1.3;'"
                )
            
            # Check for insecure protocols
            protocols_str = ' '.join(ssl_protocols)
            has_old_tls = re.search(r'TLSv1[^.23]|SSLv', protocols_str)
            has_modern = 'TLSv1.2' in protocols_str or 'TLSv1.3' in protocols_str
            
            if has_old_tls:
                return BenchmarkResult(
                    check_id="4.1.4",
                    name="Ensure only modern TLS protocols are used",
                    status=CheckStatus.FAIL,
                    details=f"Insecure TLS protocols enabled: {protocols_str}",
                    remediation="Use only TLSv1.2 and TLSv1.3"
                )
            elif has_modern:
                return BenchmarkResult(
                    check_id="4.1.4",
                    name="Ensure only modern TLS protocols are used",
                    status=CheckStatus.PASS,
                    details=f"Modern TLS protocols configured: {protocols_str}",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="4.1.4",
                    name="Ensure only modern TLS protocols are used",
                    status=CheckStatus.FAIL,
                    details=f"TLS configuration unclear: {protocols_str}",
                    remediation="Set 'ssl_protocols TLSv1.2 TLSv1.3;'"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.4",
                name="Ensure only modern TLS protocols are used",
                status=CheckStatus.ERROR,
                details=f"Error checking TLS protocols: {e}",
                remediation=""
            )
    
    def check_4_1_5_weak_ciphers(self) -> BenchmarkResult:
        """4.1.5 Disable weak ciphers."""
        try:
            config = self._get_all_configs()
            
            # Find ssl_ciphers directives (NOT proxy_ssl_ciphers)
            # This check is for client-facing SSL configuration
            ssl_ciphers = re.findall(r'(?<!proxy_)ssl_ciphers\s+[\'"]?([^;\'"]+)[\'"]?;', config)
            
            if not ssl_ciphers:
                return BenchmarkResult(
                    check_id="4.1.5",
                    name="Disable weak ciphers",
                    status=CheckStatus.WARNING,
                    details="ssl_ciphers not explicitly configured",
                    remediation="Configure strong cipher suites"
                )
            
            ciphers_str = ssl_ciphers[0]
            
            # Check for weak ciphers
            # Note: Check for patterns that indicate ENABLING weak ciphers, not DISABLING them
            weak_patterns = ['RC4', 'DES-', '3DES', 'NULL', 'EXPORT', 'anon', 'aNULL']
            has_weak = False
            for pattern in weak_patterns:
                # Check if pattern exists but NOT preceded by ! (exclusion)
                if pattern in ciphers_str and f'!{pattern}' not in ciphers_str:
                    has_weak = True
                    break
            
            # Check for strong ciphers
            has_strong = any(cipher in ciphers_str for cipher in ['ECDHE', 'AES', 'GCM', 'CHACHA20'])
            
            if has_weak:
                return BenchmarkResult(
                    check_id="4.1.5",
                    name="Disable weak ciphers",
                    status=CheckStatus.FAIL,
                    details=f"Weak ciphers may be enabled: {ciphers_str[:100]}",
                    remediation="Use only strong cipher suites (ECDHE, AES-GCM, CHACHA20)"
                )
            elif has_strong:
                return BenchmarkResult(
                    check_id="4.1.5",
                    name="Disable weak ciphers",
                    status=CheckStatus.PASS,
                    details=f"Strong cipher suites configured: {ciphers_str[:100]}...",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="4.1.5",
                    name="Disable weak ciphers",
                    status=CheckStatus.WARNING,
                    details=f"Cipher configuration unclear: {ciphers_str[:100]}",
                    remediation="Review and configure strong cipher suites"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.5",
                name="Disable weak ciphers",
                status=CheckStatus.ERROR,
                details=f"Error checking ciphers: {e}",
                remediation=""
            )
    
    def check_4_1_6_dhparam(self) -> BenchmarkResult:
        """4.1.6 Ensure custom Diffie-Hellman parameters are used."""
        try:
            config = self._get_all_configs()
            
            # Check for ssl_dhparam directive
            dhparam_match = re.search(r'ssl_dhparam\s+([^;]+);', config)
            
            if not dhparam_match:
                return BenchmarkResult(
                    check_id="4.1.6",
                    name="Ensure custom Diffie-Hellman parameters are used",
                    status=CheckStatus.FAIL,
                    details="ssl_dhparam not configured",
                    remediation="Generate and configure DH parameters: ssl_dhparam /path/to/dhparam.pem;"
                )
            
            dhparam_file = dhparam_match.group(1).strip()
            
            # Check if file exists
            exists = self.ssh.file_exists(dhparam_file)
            
            if exists:
                return BenchmarkResult(
                    check_id="4.1.6",
                    name="Ensure custom Diffie-Hellman parameters are used",
                    status=CheckStatus.PASS,
                    details=f"DH parameters configured: {dhparam_file}",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="4.1.6",
                    name="Ensure custom Diffie-Hellman parameters are used",
                    status=CheckStatus.FAIL,
                    details=f"DH parameters file not found: {dhparam_file}",
                    remediation="Generate DH parameters file"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.6",
                name="Ensure custom Diffie-Hellman parameters are used",
                status=CheckStatus.ERROR,
                details=f"Error checking DH parameters: {e}",
                remediation=""
            )
    
    def check_4_1_8_hsts(self) -> BenchmarkResult:
        """4.1.8 Ensure HTTP Strict Transport Security (HSTS) is enabled."""
        try:
            config = self._get_all_configs()
            
            # Check for HSTS header
            hsts_match = re.search(
                r'add_header\s+Strict-Transport-Security\s+[\'"]([^\'"]+)[\'"]',
                config
            )
            
            if not hsts_match:
                return BenchmarkResult(
                    check_id="4.1.8",
                    name="Ensure HTTP Strict Transport Security (HSTS) is enabled",
                    status=CheckStatus.FAIL,
                    details="HSTS header not configured",
                    remediation="Add header: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";"
                )
            
            hsts_value = hsts_match.group(1)
            
            # Check for max-age
            max_age_match = re.search(r'max-age=(\d+)', hsts_value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age >= 31536000:  # 1 year
                    return BenchmarkResult(
                        check_id="4.1.8",
                        name="Ensure HTTP Strict Transport Security (HSTS) is enabled",
                        status=CheckStatus.PASS,
                        details=f"HSTS enabled with max-age={max_age}",
                        remediation=""
                    )
                else:
                    return BenchmarkResult(
                        check_id="4.1.8",
                        name="Ensure HTTP Strict Transport Security (HSTS) is enabled",
                        status=CheckStatus.WARNING,
                        details=f"HSTS max-age too short: {max_age}",
                        remediation="Set max-age to at least 31536000 (1 year)"
                    )
            else:
                return BenchmarkResult(
                    check_id="4.1.8",
                    name="Ensure HTTP Strict Transport Security (HSTS) is enabled",
                    status=CheckStatus.FAIL,
                    details="HSTS configured but max-age not found",
                    remediation="Set proper HSTS header with max-age"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.8",
                name="Ensure HTTP Strict Transport Security (HSTS) is enabled",
                status=CheckStatus.ERROR,
                details=f"Error checking HSTS: {e}",
                remediation=""
            )
    
    def check_4_1_9_upstream_client_cert(self) -> BenchmarkResult:
        """4.1.9 Ensure upstream server traffic is authenticated with a client certificate."""
        try:
            config = self._get_all_configs()
            
            # Check if there are upstream SSL connections
            has_proxy_ssl = re.search(r'proxy_ssl_certificate', config)
            
            if not has_proxy_ssl:
                return BenchmarkResult(
                    check_id="4.1.9",
                    name="Ensure upstream traffic is authenticated with client certificate",
                    status=CheckStatus.NOT_APPLICABLE,
                    details="No upstream SSL configuration found",
                    remediation=""
                )
            
            # Check for client certificate configuration
            has_cert = re.search(r'proxy_ssl_certificate\s+[^;]+;', config)
            has_key = re.search(r'proxy_ssl_certificate_key\s+[^;]+;', config)
            
            if has_cert and has_key:
                return BenchmarkResult(
                    check_id="4.1.9",
                    name="Ensure upstream traffic is authenticated with client certificate",
                    status=CheckStatus.PASS,
                    details="Upstream client certificate configured",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="4.1.9",
                    name="Ensure upstream traffic is authenticated with client certificate",
                    status=CheckStatus.WARNING,
                    details="Upstream SSL without complete client certificate configuration",
                    remediation="Configure proxy_ssl_certificate and proxy_ssl_certificate_key"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.9",
                name="Ensure upstream traffic is authenticated with client certificate",
                status=CheckStatus.ERROR,
                details=f"Error checking upstream client cert: {e}",
                remediation=""
            )
    
    def check_4_1_12_session_resumption(self) -> BenchmarkResult:
        """4.1.12 Ensure session resumption is disabled for perfect forward secrecy."""
        try:
            config = self._get_all_configs()
            
            # Check for ssl_session_tickets off
            tickets_off = re.search(r'ssl_session_tickets\s+off', config)
            
            if tickets_off:
                return BenchmarkResult(
                    check_id="4.1.12",
                    name="Ensure session resumption is disabled for PFS",
                    status=CheckStatus.PASS,
                    details="SSL session tickets disabled",
                    remediation=""
                )
            elif re.search(r'ssl_session_tickets\s+on', config):
                return BenchmarkResult(
                    check_id="4.1.12",
                    name="Ensure session resumption is disabled for PFS",
                    status=CheckStatus.FAIL,
                    details="SSL session tickets explicitly enabled",
                    remediation="Set 'ssl_session_tickets off;' for perfect forward secrecy"
                )
            else:
                return BenchmarkResult(
                    check_id="4.1.12",
                    name="Ensure session resumption is disabled for PFS",
                    status=CheckStatus.WARNING,
                    details="ssl_session_tickets not explicitly configured (default is on)",
                    remediation="Set 'ssl_session_tickets off;' for perfect forward secrecy"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.12",
                name="Ensure session resumption is disabled for PFS",
                status=CheckStatus.ERROR,
                details=f"Error checking session tickets: {e}",
                remediation=""
            )
    
    def check_4_1_13_http2(self) -> BenchmarkResult:
        """4.1.13 Ensure HTTP/2.0 is used."""
        try:
            config = self._get_all_configs()
            
            # Check for http2 in listen directives (old syntax: listen 443 ssl http2)
            has_http2_old = re.search(r'listen\s+.*443.*http2', config)
            
            # Check for http2 on directive (new syntax: http2 on;)
            has_http2_new = re.search(r'http2\s+on', config)
            
            if has_http2_old or has_http2_new:
                if has_http2_new:
                    return BenchmarkResult(
                        check_id="4.1.13",
                        name="Ensure HTTP/2.0 is used",
                        status=CheckStatus.PASS,
                        details="HTTP/2 is enabled on HTTPS (using 'http2 on;' directive)",
                        remediation=""
                    )
                else:
                    return BenchmarkResult(
                        check_id="4.1.13",
                        name="Ensure HTTP/2.0 is used",
                        status=CheckStatus.PASS,
                        details="HTTP/2 is enabled on HTTPS (using 'listen ... http2' directive)",
                        remediation=""
                    )
            else:
                return BenchmarkResult(
                    check_id="4.1.13",
                    name="Ensure HTTP/2.0 is used",
                    status=CheckStatus.FAIL,
                    details="HTTP/2 not enabled",
                    remediation="Enable HTTP/2: Add 'http2 on;' directive in server block with HTTPS"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.13",
                name="Ensure HTTP/2.0 is used",
                status=CheckStatus.ERROR,
                details=f"Error checking HTTP/2: {e}",
                remediation=""
            )
        except Exception as e:
            return BenchmarkResult(
                check_id="4.1.13",
                name="Ensure HTTP/2.0 is used",
                status=CheckStatus.ERROR,
                details=f"Error checking HTTP/2: {e}",
                remediation=""
            )
    
    # ==================== 5. Request Filtering ====================
    
    def check_5_2_1_client_timeouts(self) -> BenchmarkResult:
        """5.2.1 Ensure timeout values for reading client header and body are set correctly."""
        try:
            config = self._get_all_configs()
            
            # Check client timeouts
            body_timeout = re.findall(r'client_body_timeout\s+(\d+)', config)
            header_timeout = re.findall(r'client_header_timeout\s+(\d+)', config)
            
            issues = []
            
            if not body_timeout:
                issues.append("client_body_timeout not configured")
            elif int(body_timeout[0]) > 10:
                issues.append(f"client_body_timeout too high: {body_timeout[0]}s")
            
            if not header_timeout:
                issues.append("client_header_timeout not configured")
            elif int(header_timeout[0]) > 10:
                issues.append(f"client_header_timeout too high: {header_timeout[0]}s")
            
            if issues:
                return BenchmarkResult(
                    check_id="5.2.1",
                    name="Ensure client timeout values are set correctly",
                    status=CheckStatus.FAIL if len(issues) > 1 else CheckStatus.WARNING,
                    details="; ".join(issues),
                    remediation="Set client_body_timeout and client_header_timeout to 10s or less"
                )
            else:
                return BenchmarkResult(
                    check_id="5.2.1",
                    name="Ensure client timeout values are set correctly",
                    status=CheckStatus.PASS,
                    details=f"Client timeouts configured: body={body_timeout[0]}s, header={header_timeout[0]}s",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="5.2.1",
                name="Ensure client timeout values are set correctly",
                status=CheckStatus.ERROR,
                details=f"Error checking client timeouts: {e}",
                remediation=""
            )
    
    def check_5_2_2_max_body_size(self) -> BenchmarkResult:
        """5.2.2 Ensure the maximum request body size is set correctly."""
        try:
            config = self._get_all_configs()
            
            # Find client_max_body_size
            max_body = re.findall(r'client_max_body_size\s+(\d+[kKmMgG]?)', config)
            
            if not max_body:
                return BenchmarkResult(
                    check_id="5.2.2",
                    name="Ensure maximum request body size is set correctly",
                    status=CheckStatus.WARNING,
                    details="client_max_body_size not configured (default 1m)",
                    remediation="Set appropriate client_max_body_size limit"
                )
            else:
                return BenchmarkResult(
                    check_id="5.2.2",
                    name="Ensure maximum request body size is set correctly",
                    status=CheckStatus.PASS,
                    details=f"client_max_body_size configured: {max_body[0]}",
                    remediation=""
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="5.2.2",
                name="Ensure maximum request body size is set correctly",
                status=CheckStatus.ERROR,
                details=f"Error checking max body size: {e}",
                remediation=""
            )
    
    def check_5_2_3_buffer_size(self) -> BenchmarkResult:
        """5.2.3 Ensure the maximum buffer size for URIs is defined."""
        try:
            config = self._get_all_configs()
            
            # Check buffer directives
            has_large_client_header = re.search(r'large_client_header_buffers', config)
            has_client_body_buffer = re.search(r'client_body_buffer_size', config)
            has_client_header_buffer = re.search(r'client_header_buffer_size', config)
            
            configured = []
            if has_large_client_header:
                configured.append("large_client_header_buffers")
            if has_client_body_buffer:
                configured.append("client_body_buffer_size")
            if has_client_header_buffer:
                configured.append("client_header_buffer_size")
            
            if len(configured) >= 2:
                return BenchmarkResult(
                    check_id="5.2.3",
                    name="Ensure maximum buffer size for URIs is defined",
                    status=CheckStatus.PASS,
                    details=f"Buffer sizes configured: {', '.join(configured)}",
                    remediation=""
                )
            elif len(configured) == 1:
                return BenchmarkResult(
                    check_id="5.2.3",
                    name="Ensure maximum buffer size for URIs is defined",
                    status=CheckStatus.WARNING,
                    details=f"Partial buffer configuration: {configured[0]}",
                    remediation="Configure all buffer size directives"
                )
            else:
                return BenchmarkResult(
                    check_id="5.2.3",
                    name="Ensure maximum buffer size for URIs is defined",
                    status=CheckStatus.FAIL,
                    details="Buffer sizes not configured",
                    remediation="Configure client buffer size directives"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="5.2.3",
                name="Ensure maximum buffer size for URIs is defined",
                status=CheckStatus.ERROR,
                details=f"Error checking buffer sizes: {e}",
                remediation=""
            )
    
    def check_5_3_1_x_frame_options(self) -> BenchmarkResult:
        """5.3.1 Ensure X-Frame-Options header is configured and enabled."""
        try:
            config = self._get_all_configs()
            
            # Check for X-Frame-Options header
            xfo_match = re.search(
                r'add_header\s+X-Frame-Options\s+[\'"]?([^\'";\s]+)[\'"]?',
                config
            )
            
            if xfo_match:
                value = xfo_match.group(1)
                if value.upper() in ['DENY', 'SAMEORIGIN']:
                    return BenchmarkResult(
                        check_id="5.3.1",
                        name="Ensure X-Frame-Options header is configured",
                        status=CheckStatus.PASS,
                        details=f"X-Frame-Options configured: {value}",
                        remediation=""
                    )
                else:
                    return BenchmarkResult(
                        check_id="5.3.1",
                        name="Ensure X-Frame-Options header is configured",
                        status=CheckStatus.WARNING,
                        details=f"X-Frame-Options has unexpected value: {value}",
                        remediation="Set to DENY or SAMEORIGIN"
                    )
            else:
                return BenchmarkResult(
                    check_id="5.3.1",
                    name="Ensure X-Frame-Options header is configured",
                    status=CheckStatus.FAIL,
                    details="X-Frame-Options header not configured",
                    remediation="Add header: add_header X-Frame-Options \"SAMEORIGIN\";"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="5.3.1",
                name="Ensure X-Frame-Options header is configured",
                status=CheckStatus.ERROR,
                details=f"Error checking X-Frame-Options: {e}",
                remediation=""
            )
    
    def check_5_3_2_x_content_type_options(self) -> BenchmarkResult:
        """5.3.2 Ensure X-Content-Type-Options header is configured and enabled."""
        try:
            config = self._get_all_configs()
            
            # Check for X-Content-Type-Options header
            xcto_match = re.search(
                r'add_header\s+X-Content-Type-Options\s+[\'"]?nosniff[\'"]?',
                config,
                re.IGNORECASE
            )
            
            if xcto_match:
                return BenchmarkResult(
                    check_id="5.3.2",
                    name="Ensure X-Content-Type-Options header is configured",
                    status=CheckStatus.PASS,
                    details="X-Content-Type-Options configured: nosniff",
                    remediation=""
                )
            else:
                return BenchmarkResult(
                    check_id="5.3.2",
                    name="Ensure X-Content-Type-Options header is configured",
                    status=CheckStatus.FAIL,
                    details="X-Content-Type-Options header not configured",
                    remediation="Add header: add_header X-Content-Type-Options \"nosniff\";"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="5.3.2",
                name="Ensure X-Content-Type-Options header is configured",
                status=CheckStatus.ERROR,
                details=f"Error checking X-Content-Type-Options: {e}",
                remediation=""
            )
    
    def check_5_3_3_csp(self) -> BenchmarkResult:
        """5.3.3 Ensure Content Security Policy (CSP) is enabled and configured properly."""
        try:
            config = self._get_all_configs()
            
            # Check for CSP header
            csp_match = re.search(
                r'add_header\s+Content-Security-Policy\s+[\'"]([^\'"]+)[\'"]',
                config
            )
            
            if csp_match:
                csp_value = csp_match.group(1)
                
                # Check for basic CSP directives
                has_default_src = 'default-src' in csp_value
                
                if has_default_src:
                    return BenchmarkResult(
                        check_id="5.3.3",
                        name="Ensure Content Security Policy (CSP) is configured",
                        status=CheckStatus.PASS,
                        details="CSP header configured with default-src",
                        remediation=""
                    )
                else:
                    return BenchmarkResult(
                        check_id="5.3.3",
                        name="Ensure Content Security Policy (CSP) is configured",
                        status=CheckStatus.WARNING,
                        details="CSP configured but missing default-src directive",
                        remediation="Add default-src directive to CSP"
                    )
            else:
                return BenchmarkResult(
                    check_id="5.3.3",
                    name="Ensure Content Security Policy (CSP) is configured",
                    status=CheckStatus.FAIL,
                    details="Content-Security-Policy header not configured",
                    remediation="Add CSP header: add_header Content-Security-Policy \"default-src 'self'\";"
                )
        except Exception as e:
            return BenchmarkResult(
                check_id="5.3.3",
                name="Ensure Content Security Policy (CSP) is configured",
                status=CheckStatus.ERROR,
                details=f"Error checking CSP: {e}",
                remediation=""
            )

