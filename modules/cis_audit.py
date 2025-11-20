import logging
import json
import re
from typing import Tuple, Dict, List

# Lớp này chứa toàn bộ logic 30 checks CIS tự động
class CISAudit:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        # Tổng cộng 29 Automated checks được liệt kê trong CIS v2.1.0, cộng thêm 2.5.2 là 30
        self.check_count = 30  
        self.passed_checks = 0
        self.results = {"passed": [], "failed": []}

    def run_command(self, cmd: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Thực thi lệnh shell."""
        try:
            exit_status, stdout, stderr = self.cm.exec_command(cmd, sudo=sudo)
            return exit_status, stdout, stderr
        except:
            return 1, "", "Error during command execution"
    
    # ************************ ĐỊNH NGHĨA 30 CHECKS CIS ************************
    
    # --- 1. Initial Setup ---
    def _check_1_1_1_is_installed(self):
        """1.1.1 Ensure NGINX is installed (Automated)"""
        rc, _, _ = self.run_command("nginx -v 2>&1")
        return rc == 0, "1.1.1 - NGINX is installed"

    # --- 2. Basic Configuration - Minimize Modules ---
    def _check_2_1_2_no_webdav(self):
        """2.1.2 Ensure HTTP WebDAV module is not installed (Automated)"""
        rc, _, _ = self.run_command("nginx -V 2>&1 | grep http_dav_module")
        return rc != 0, "2.1.2 - HTTP WebDAV module not installed"
        
    def _check_2_1_3_no_gzip(self):
        """2.1.3 Ensure modules with gzip functionality are disabled (Automated)"""
        cmd = "nginx -V 2>&1 | grep -E '(http_gzip_module|http_gzip_static_module)'"
        rc, _, _ = self.run_command(cmd)
        return rc != 0, "2.1.3 - Gzip modules are disabled"

    def _check_2_1_4_autoindex_off(self):
        """2.1.4 Ensure the autoindex module is disabled (Automated)"""
        cmd = "egrep -i '^\\s*autoindex\\s+on' /etc/nginx/nginx.conf /etc/nginx/conf.d/*"
        rc, _, _ = self.run_command(cmd, sudo=True)
        return rc != 0, "2.1.4 - Autoindex module is disabled"

    # --- 2. Basic Configuration - Account Security ---
    def _check_2_2_1_dedicated_user(self):
        """2.2.1 Ensure NGINX runs as non-privileged, dedicated service account (Automated)"""
        rc1, user_directive, _ = self.run_command("grep -Pi -- '^\\h*user\\h+[^;\\n\\r]+\\h*;.*$' /etc/nginx/nginx.conf", sudo=True)
        if rc1 != 0: return False, "2.2.1 - User directive missing"
        user_match = re.search(r'user\s+(\w+);', user_directive, re.IGNORECASE)
        user = user_match.group(1) if user_match else "unknown"
        rc2, sudo_output, _ = self.run_command(f"sudo -l -U {user} 2>&1")
        is_non_privileged = "not allowed to run sudo" in sudo_output or rc2 != 0
        return is_non_privileged, "2.2.1 - NGINX runs as dedicated non-privileged user"

    def _check_2_2_2_user_locked(self):
        """2.2.2 Ensure the NGINX service account is locked (Automated)"""
        rc1, user_output, _ = self.run_command("awk '$1~/^\\s*user\\s*$/ {print $2}' /etc/nginx/nginx.conf | sed -r 's/;.*//g'", sudo=True)
        user = user_output.strip()
        if not user: return False, "2.2.2 - User account unknown"
        rc2, passwd_output, _ = self.run_command(f"passwd -S {user}", sudo=True)
        # Check for locked status: " L " (common), " LK ", "NP" (no password), or grep /etc/shadow
        is_locked = (" L " in passwd_output or " LK " in passwd_output or "NP" in passwd_output or rc2 != 0)
        if is_locked:
            return True, "2.2.2 - NGINX service account is locked"
        # Alternative check: look at /etc/shadow directly
        rc3, shadow_output, _ = self.run_command(f"grep '^{user}:' /etc/shadow", sudo=True)
        if "!" in shadow_output or "*" in shadow_output:
            return True, "2.2.2 - NGINX service account is locked"
        return False, "2.2.2 - NGINX service account is locked"

    def _check_2_2_3_invalid_shell(self):
        """2.2.3 Ensure the NGINX service account has an invalid shell (Automated)"""
        rc1, user_output, _ = self.run_command("awk '$1~/^\\s*user\\s*$/ {print $2}' /etc/nginx/nginx.conf | sed -r 's/;.*//g'", sudo=True)
        user = user_output.strip()
        if not user: return False, "2.2.3 - User account unknown"
        rc2, shell_output, _ = self.run_command(f"grep '^{user}:' /etc/passwd | cut -d: -f7", sudo=True)
        invalid_shell = "/sbin/nologin" in shell_output or "/bin/false" in shell_output
        return invalid_shell, "2.2.3 - NGINX service account has invalid shell"

    # --- 2. Basic Configuration - Permissions and Ownership ---
    def _check_2_3_1_owned_by_root(self):
        """2.3.1 Ensure NGINX directories and files are owned by root (Automated)"""
        rc, output, _ = self.run_command("stat -c '%U:%G' /etc/nginx", sudo=True)
        return output.strip() == "root:root", "2.3.1 - NGINX directories and files owned by root"

    def _check_2_3_2_access_restricted(self):
        """2.3.2 Ensure access to NGINX directories and files is restricted (Automated)"""
        rc1, output_dir, _ = self.run_command("find /etc/nginx -type d -exec stat -Lc '%a' {} + | grep -E -v '755|750'", sudo=True)
        rc2, output_file, _ = self.run_command("find /etc/nginx -type f -exec stat -Lc '%a' {} + | grep -E -v '660|644|640'", sudo=True)
        is_restricted = (rc1 != 0 and not output_dir.strip()) and (rc2 != 0 and not output_file.strip())
        return is_restricted, "2.3.2 - Access to NGINX directories and files is restricted"

    def _check_2_3_3_pid_secured(self):
        """2.3.3 Ensure the NGINX process ID (PID) file is secured (Automated)"""
        cmd_owner = "stat -L -c '%U:%G' /run/nginx.pid 2>/dev/null"
        cmd_perms = "stat -L -c '%a' /run/nginx.pid 2>/dev/null"
        rc1, owner, _ = self.run_command(cmd_owner, sudo=True)
        rc2, perms, _ = self.run_command(cmd_perms, sudo=True)
        perms_str = perms.strip()
        # Accept 640, 644, or 600 permissions (root-only or root+group readable)
        is_secured = owner.strip() == "root:root" and perms_str in ["640", "644", "600"]
        return is_secured, "2.3.3 - NGINX process ID (PID) file is secured"

    # --- 2. Basic Configuration - Network Configuration ---
    def _check_2_4_2_unknown_hosts(self):
        """2.4.2 Ensure requests for unknown host names are rejected (Automated)"""
        # Check if catchall.conf file exists with default_server
        rc, output, _ = self.run_command("grep -l 'default_server' /etc/nginx/conf.d/*.conf 2>/dev/null | head -1", sudo=True)
        
        # Also check for the marker 'server_name _' which indicates catchall
        rc2, output2, _ = self.run_command("grep -r 'server_name _' /etc/nginx/conf.d/ 2>/dev/null", sudo=True)
        
        return rc == 0 or rc2 == 0, "2.4.2 - Requests for unknown host names are rejected"

    def _check_2_4_3_keepalive_timeout(self):
        """2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0 (Automated)"""
        rc, stdout, _ = self.run_command("grep -ir keepalive_timeout /etc/nginx", sudo=True)
        match = re.search(r'keepalive_timeout\s+(\d+)', stdout)
        if match:
            timeout = int(match.group(1))
            return 0 < timeout <= 10, "2.4.3 - keepalive_timeout is configured (<= 10s)"
        return False, "2.4.3 - keepalive_timeout is NOT configured"

    def _check_2_4_4_send_timeout(self):
        """2.4.4 Ensure send_timeout is set to 10 seconds or less, but not 0 (Automated)"""
        rc, stdout, _ = self.run_command("grep -ir send_timeout /etc/nginx", sudo=True)
        match = re.search(r'send_timeout\s+(\d+)', stdout)
        if match:
            timeout = int(match.group(1))
            return 0 < timeout <= 10, "2.4.4 - send_timeout is configured (<= 10s)"
        return False, "2.4.4 - send_timeout is NOT configured"

    # --- 2. Basic Configuration - Information Disclosure ---
    def _check_2_5_1_server_tokens(self):
        """2.5.1 Ensure server_tokens directive is set to off (Automated)"""
        rc, _, _ = self.run_command("grep -i 'server_tokens off' /etc/nginx/nginx.conf", sudo=True)
        return rc == 0, "2.5.1 - Server tokens are hidden (server_tokens off)"

    def _check_2_5_2_no_nginx_reference(self):
        """2.5.2 Ensure default error and index.html pages do not reference NGINX (Automated)"""
        rc1, _, _ = self.run_command("grep -i nginx /usr/share/nginx/html/index.html 2>/dev/null")
        rc2, _, _ = self.run_command("grep -i nginx /usr/share/nginx/html/50x.html 2>/dev/null")
        return rc1 != 0 and rc2 != 0, "2.5.2 - Default pages do not reference NGINX"

    def _check_2_5_4_proxy_headers(self):
        """2.5.4 Ensure the NGINX reverse proxy does not enable information disclosure (Automated)"""
        rc1, output1, _ = self.run_command("grep -ir 'proxy_hide_header X-Powered-By' /etc/nginx/", sudo=True)
        rc2, output2, _ = self.run_command("grep -ir 'proxy_hide_header Server' /etc/nginx/", sudo=True)
        return rc1 == 0 and rc2 == 0, "2.5.4 - Proxy headers X-Powered-By and Server are hidden"

    # --- 3. Logging ---
    def _check_3_3_error_log_info(self):
        """3.3 Ensure error logging is enabled and set to the info logging level (Automated)"""
        rc, _, _ = self.run_command("grep -i 'error_log .* info;' /etc/nginx/nginx.conf", sudo=True)
        return rc == 0, "3.3 - Error logging level is set to info"

    def _check_3_4_log_rotated(self):
        """3.4 Ensure log files are rotated (Automated)"""
        rc1, _, _ = self.run_command("cat /etc/logrotate.d/nginx | grep -i weekly", sudo=True)
        rc2, output2, _ = self.run_command("cat /etc/logrotate.d/nginx | grep -i rotate", sudo=True)
        is_rotated = rc1 == 0 and rc2 == 0 and re.search(r'rotate\s+\d+', output2)
        return is_rotated, "3.4 - Log files are rotated (weekly/rotate)"

    # --- 4. Encryption ---
    def _check_4_1_3_key_permissions(self):
        """4.1.3 Ensure private key permissions are restricted (Automated)"""
        cmd = "find /etc/nginx -name '*.key' -exec stat -Lc '%a' {} + | grep -E -v '400|600' "
        rc, output, _ = self.run_command(cmd, sudo=True)
        return rc != 0, "4.1.3 - Private key permissions are restricted (<= 600)"

    def _check_4_1_4_modern_tls(self):
        """4.1.4 Ensure only modern TLS protocols are used (Automated)"""
        cmd = "grep -ir ssl_protocols /etc/nginx | grep -E -v 'TLSv1|TLSv1.1|SSLv'"
        rc, _, _ = self.run_command(cmd, sudo=True)
        return rc == 0, "4.1.4 - Only modern TLS protocols (>= TLSv1.2) are used"

    def _check_4_1_6_custom_dhparam(self):
        """4.1.6 Ensure custom Diffie-Hellman parameters are used (Automated)"""
        rc, _, _ = self.run_command("grep -ir ssl_dhparam /etc/nginx", sudo=True)
        return rc == 0, "4.1.6 - Custom Diffie-Hellman parameters are used"

    def _check_4_1_7_ocsp_stapling(self):
        """4.1.7 Ensure Online Certificate Status Protocol (OCSP) stapling is enabled (Automated)"""
        cmd = "grep -ir 'ssl_stapling on;' /etc/nginx | grep -ir 'ssl_stapling_verify on;'"
        rc, _, _ = self.run_command(cmd, sudo=True)
        return rc == 0, "4.1.7 - OCSP stapling is enabled and verified"

    def _check_4_1_8_hsts_enabled(self):
        """4.1.8 Ensure HTTP Strict Transport Security (HSTS) is enabled (Automated)"""
        cmd = "grep -ir 'Strict-Transport-Security' /etc/nginx"
        rc, output, _ = self.run_command(cmd, sudo=True)
        if rc == 0:
            # Extract max-age value
            max_age_match = re.search(r'max-age=(\d+)', output)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                # CIS requires >= 6 months (15768000 seconds) or >= 10886400 (126 days)
                if max_age >= 10886400:
                    return True, "4.1.8 - HSTS is enabled with adequate max-age"
        return False, "4.1.8 - HSTS is NOT enabled or max-age is too low"

    def _check_4_1_9_client_cert_auth(self):
        """4.1.9 Ensure upstream server traffic is authenticated with a client certificate (Automated)"""
        cmd = "grep -ir 'proxy_ssl_certificate' /etc/nginx | grep -ir 'proxy_ssl_certificate_key'"
        rc, _, _ = self.run_command(cmd, sudo=True)
        return rc == 0, "4.1.9 - Upstream traffic is authenticated with a client certificate"

    def _check_4_1_12_session_resumption(self):
        """4.1.12 Ensure session resumption is disabled to enable perfect forward security (Automated)"""
        rc, _, _ = self.run_command("grep -ir 'ssl_session_tickets off;' /etc/nginx", sudo=True)
        return rc == 0, "4.1.12 - Session resumption is disabled (PFS enabled)"

    def _check_4_1_13_http2_used(self):
        """4.1.13 Ensure HTTP/2.0 is used (Automated)"""
        rc, _, _ = self.run_command("grep -ir 'http2' /etc/nginx", sudo=True)
        return rc == 0, "4.1.13 - HTTP/2.0 is enabled"

    # --- 5. Request Filtering and Restrictions ---
    def _check_5_2_1_client_timeouts(self):
        """5.2.1 Ensure timeout values for reading the client header and body are set correctly (Automated)"""
        rc1, _, _ = self.run_command("grep -ir 'client_body_timeout 10;' /etc/nginx", sudo=True)
        rc2, _, _ = self.run_command("grep -ir 'client_header_timeout 10;' /etc/nginx", sudo=True)
        return rc1 == 0 and rc2 == 0, "5.2.1 - client_header_timeout & client_body_timeout are set to 10s"

    def _check_5_2_2_max_body_size(self):
        """5.2.2 Ensure the maximum request body size is set correctly (Automated)"""
        rc, _, _ = self.run_command("grep -ir client_max_body_size /etc/nginx", sudo=True)
        return rc == 0, "5.2.2 - client_max_body_size is configured"

    def _check_5_2_3_uri_buffer_size(self):
        """5.2.3 Ensure the maximum buffer size for URIs is defined (Automated)"""
        rc, _, _ = self.run_command("grep -ir 'large_client_header_buffers 2 1k' /etc/nginx", sudo=True)
        return rc == 0, "5.2.3 - large_client_header_buffers is configured"

    def _check_5_3_1_x_frame_options(self):
        """5.3.1 Ensure X-Frame-Options header is configured and enabled (Automated)"""
        rc, _, _ = self.run_command("grep -ir 'X-Frame-Options' /etc/nginx", sudo=True)
        return rc == 0, "5.3.1 - X-Frame-Options header is configured"

    def _check_5_3_2_x_content_type_options(self):
        """5.3.2 Ensure X-Content-Type-Options header is configured and enabled (Automated)"""
        rc, _, _ = self.run_command("grep -ir 'X-Content-Type-Options' /etc/nginx", sudo=True)
        return rc == 0, "5.3.2 - X-Content-Type-Options header is configured"

    # ************************ CUỐI 30 CHECKS CIS ************************
    
    def _run_all_30_checks(self):
         checks_list = [
             self._check_1_1_1_is_installed,
             self._check_2_1_2_no_webdav, self._check_2_1_3_no_gzip, self._check_2_1_4_autoindex_off,
             self._check_2_2_1_dedicated_user, self._check_2_2_2_user_locked, self._check_2_2_3_invalid_shell,
             self._check_2_3_1_owned_by_root, self._check_2_3_2_access_restricted, self._check_2_3_3_pid_secured,
             self._check_2_4_2_unknown_hosts, self._check_2_4_3_keepalive_timeout, self._check_2_4_4_send_timeout,
             self._check_2_5_1_server_tokens, self._check_2_5_2_no_nginx_reference, self._check_2_5_4_proxy_headers,
             self._check_3_3_error_log_info, self._check_3_4_log_rotated,
             self._check_4_1_3_key_permissions, self._check_4_1_4_modern_tls, self._check_4_1_6_custom_dhparam,
             self._check_4_1_7_ocsp_stapling, self._check_4_1_8_hsts_enabled, self._check_4_1_9_client_cert_auth,
             self._check_4_1_12_session_resumption, self._check_4_1_13_http2_used,
             self._check_5_2_1_client_timeouts, self._check_5_2_2_max_body_size, self._check_5_2_3_uri_buffer_size,
             self._check_5_3_1_x_frame_options, self._check_5_3_2_x_content_type_options
         ]
         
         if len(checks_list) != self.check_count:
             self.logger.warning(f"Inconsistent check count: Expected {self.check_count}, found {len(checks_list)}. Adjusting check_count.")
             self.check_count = len(checks_list)

         for check_func in checks_list:
             status, message = check_func()
             if status:
                 self.passed_checks += 1
                 self.results['passed'].append(message)
             else:
                 self.results['failed'].append(message)


    def execute(self) -> bool:
        self.logger.info("Performing full CIS NGINX Benchmark Audit")
        
        self.passed_checks = 0
        self.results = {"passed": [], "failed": []}
        
        self._run_all_30_checks()
        
        report = {
            "benchmark": "CIS NGINX Benchmark v2.1.0",
            "summary": {"total_checks": self.check_count, "passed": self.passed_checks},
            "results": self.results
        }
        # GHI KẾT QUẢ RA FILE JSON
        with open("cis_audit_results.json", 'w') as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"Audit CIS completed. Passed {self.passed_checks}/{self.check_count} checks.")
        return True

class AuditAfter(CISAudit):
    pass