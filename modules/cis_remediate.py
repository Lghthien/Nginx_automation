import logging
from typing import Tuple
import re

class CISRemediate:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 13  # 13 remediation steps
        self.passed_checks = 0
        self.nginx_dir = "/etc/nginx"
        self.nginx_conf_path = "/etc/nginx/nginx.conf"
        self.remediation_steps = 13

    def run_command(self, cmd: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Thực thi lệnh shell."""
        try:
            exit_status, stdout, stderr = self.cm.exec_command(cmd, sudo=sudo)
            return exit_status, stdout, stderr
        except Exception as e:
            self.logger.error(f"Command execution failed: {cmd}, Error: {e}")
            return 1, "", str(e)

    # --- HÀM HELPER ĐỂ CẬP NHẬT DIRECTIVE TRONG KHỐI HTTP/MAIN (FIX CÚ PHÁP) ---
    def _add_or_update_http_directive(self, directive: str, value: str):
        """Thêm/Cập nhật directive vào khối http, đảm bảo cú pháp an toàn."""
        
        # 1. Xóa tất cả các dòng cũ của directive này
        cmd_delete = f"sudo sed -i '/{directive}/d' {self.nginx_conf_path}"
        
        # 2. Chèn dòng mới vào khối http (chèn sau dòng 'http {')
        # FIX CÚ PHÁP: Đừng thêm ';' nếu value đã chứa nó
        if value.endswith(';'):
            value_clean = value[:-1]
        else:
            value_clean = value
        
        cmd_insert = f"sudo sed -i '/http {{/a \\    {directive} {value_clean};' {self.nginx_conf_path}"
        
        self.run_command(cmd_delete) 
        self.run_command(cmd_insert)
        self.logger.info(f"Updated HTTP directive: {directive} {value_clean};")

    # --- CÁC HÀM KHẮC PHỤC CHÍNH ---

    def _add_security_headers(self):
        """Khắc phục CIS 5.3.1 (X-Frame-Options) và 5.3.2 (X-Content-Type-Options)"""
        # Xóa header cũ nếu tồn tại
        self.run_command("sudo sed -i '/X-Frame-Options/d' /etc/nginx/nginx.conf")
        self.run_command("sudo sed -i '/X-Content-Type-Options/d' /etc/nginx/nginx.conf")
        
        # Thêm headers vào http block an toàn
        self._add_or_update_http_directive("add_header X-Frame-Options", '"SAMEORIGIN" always')
        self._add_or_update_http_directive("add_header X-Content-Type-Options", '"nosniff" always')
        
        self.logger.info("Applied security headers into http block.")

    def _remediate_2_4_3_keepalive_timeout(self):
        """2.4.3 Ensure keepalive_timeout is 10 seconds or less"""
        self._add_or_update_http_directive("keepalive_timeout", "10")

    def _remediate_2_4_4_send_timeout(self):
        """2.4.4 Ensure send_timeout is set to 10 seconds or less"""
        self._add_or_update_http_directive("send_timeout", "10")

    def _remediate_2_3_2_restrict_perms(self):
        """2.3.2 Ensure access to NGINX directories and files is restricted"""
        self.run_command(f"find {self.nginx_dir} -type d -exec chmod go-w {{}} +")
        self.run_command(f"find {self.nginx_dir} -type f -exec chmod ug-x,o-rwx {{}} +")
        self.logger.info("Restricted permissions on NGINX directories and files.")

    def _remediate_5_2_1_client_timeouts(self):
        """5.2.1 Ensure client_header_timeout and client_body_timeout are set to 10s"""
        self._add_or_update_http_directive("client_body_timeout", "10")
        self._add_or_update_http_directive("client_header_timeout", "10")

    def _remediate_5_2_3_uri_buffer_size(self):
        """5.2.3 Ensure the maximum buffer size for URIs is defined (2 1k)"""
        self._add_or_update_http_directive("large_client_header_buffers", "2 1k")

    def _remediate_2_2_2_user_lock(self):
        """2.2.2 Ensure the NGINX service account is locked"""
        self.run_command("passwd -l nginx", sudo=True)
        self.logger.info("Locked nginx user account.")

    def _remediate_2_5_2_default_pages(self):
        """2.5.2 Ensure default pages do not reference NGINX"""
        # Xóa hoặc thay thế default index.html
        self.run_command("sudo rm -f /usr/share/nginx/html/index.html", sudo=True)
        
        # Tạo default page không mention NGINX (sử dụng cat heredoc)
        cmd = """cat > /tmp/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Server is operational</h1>
    <p>Default page - no version information exposed.</p>
</body>
</html>
EOF
sudo mv /tmp/index.html /usr/share/nginx/html/index.html
sudo chmod 644 /usr/share/nginx/html/index.html"""
        
        self.run_command(cmd, sudo=True)
        self.logger.info("Replaced default index page to not reference NGINX.")

    def _remediate_2_5_4_proxy_headers(self):
        """2.5.4 Ensure proxy headers (X-Powered-By, Server) are hidden"""
        # Thêm proxy_hide_header directives vào http block
        self._add_or_update_http_directive("proxy_hide_header X-Powered-By", '')
        self._add_or_update_http_directive("proxy_hide_header Server", '')
        self.logger.info("Configured proxy header hiding.")

    def _remediate_2_4_2_unknown_hosts(self):
        """2.4.2 Ensure requests for unknown host names are rejected (return 444)"""
        # Xóa file cũ
        self.run_command('sudo rm -f /etc/nginx/conf.d/catchall.conf /etc/nginx/conf.d/default.conf', sudo=True)
        
        # Write the catchall config step by step to avoid multiline issues
        lines = [
            'server {',
            '    listen 80 default_server;',
            '    listen [::]:80 default_server;',
            '    server_name _;',
            '    return 444;',
            '}'
        ]
        
        # Create file using printf  with echo
        for i, line in enumerate(lines):
            if i == 0:
                # First line creates file
                self.run_command(f"echo '{line}' | sudo tee /etc/nginx/conf.d/catchall.conf > /dev/null", sudo=False)
            else:
                # Append remaining lines
                self.run_command(f"echo '{line}' | sudo tee -a /etc/nginx/conf.d/catchall.conf > /dev/null", sudo=False)
        
        self.run_command("sudo chmod 644 /etc/nginx/conf.d/catchall.conf", sudo=True)
        self.logger.info("Configured catch-all server block to reject unknown hosts.")

    def _remediate_5_2_2_max_body_size(self):
        """5.2.2 Ensure client_max_body_size is configured"""
        self._add_or_update_http_directive("client_max_body_size", "1m")
        self.logger.info("Configured client_max_body_size to 1m.")

    def _remediate_2_3_3_pid_file_perms(self):
        """2.3.3 Ensure NGINX process ID (PID) file is secured"""
        # Tìm PID file và thiết lập quyền truy cập
        rc, pid_output, _ = self.run_command("grep -r 'pid ' /etc/nginx/nginx.conf | head -1", sudo=True)
        if rc == 0 and pid_output:
            # Lấy đường dẫn PID file từ config
            pid_match = re.search(r'pid\s+([^;]+);', pid_output)
            if pid_match:
                pid_path = pid_match.group(1).strip()
                # Đảm bảo PID file chỉ được root truy cập: 644 hoặc 640
                self.run_command(f"sudo touch {pid_path}", sudo=True)
                self.run_command(f"sudo chmod 640 {pid_path}", sudo=True)
                self.run_command(f"sudo chown root:root {pid_path}", sudo=True)
                self.logger.info(f"Secured PID file permissions: {pid_path}")
        else:
            # Nếu không tìm thấy, sử dụng default
            self.run_command("sudo chmod 640 /run/nginx.pid", sudo=True)
            self.run_command("sudo chown root:root /run/nginx.pid", sudo=True)
            self.logger.info("Secured default PID file permissions")

    def _remediate_4_1_8_hsts_header(self):
        """4.1.8 Ensure HSTS is enabled with appropriate max-age"""
        # Thêm HSTS header vào http block (min 6 months = 15768000 seconds)
        self.run_command("sudo sed -i '/add_header Strict-Transport-Security/d' /etc/nginx/nginx.conf")
        self._add_or_update_http_directive("add_header Strict-Transport-Security", '"max-age=15768000; includeSubDomains" always')
        self.logger.info("Configured HSTS header with 6-month max-age")


    def execute(self):
        """Thực thi toàn bộ các bước khắc phục tự động."""
        self.logger.info("Applying full CIS NGINX Automated Remediation")
        
        # Tạo backup nginx.conf trước khi sửa
        self.run_command(f"sudo cp {self.nginx_conf_path} {self.nginx_conf_path}.backup")
        self.logger.debug("Created backup of nginx.conf")
        
        # Xóa các file config cũ để tránh trùng lặp
        self.run_command("sudo rm -f /etc/nginx/conf.d/catchall.conf")
        self.run_command("sudo rm -f /etc/nginx/conf.d/default.conf")
        self.logger.debug("Cleaned up old conf.d files")
        
        remediations = [
            self._add_security_headers,          
            self._remediate_2_2_2_user_lock,
            self._remediate_2_4_2_unknown_hosts,
            self._remediate_2_4_3_keepalive_timeout, 
            self._remediate_2_4_4_send_timeout,      
            self._remediate_2_3_2_restrict_perms,    
            self._remediate_2_5_2_default_pages,
            self._remediate_2_5_4_proxy_headers,
            self._remediate_5_2_1_client_timeouts,   
            self._remediate_5_2_3_uri_buffer_size,   
            self._remediate_5_2_2_max_body_size,
            self._remediate_2_3_3_pid_file_perms,
            self._remediate_4_1_8_hsts_header
        ]
        
        success_count = 0
        self.remediation_steps = len(remediations)
        
        for remediation in remediations:
            try:
                remediation()
                success_count += 1
            except Exception as e:
                self.logger.error(f"Remediation failed for {remediation.__name__}: {e}")

        self.passed_checks = 1 if success_count == self.remediation_steps else 0
        self.logger.info(f"Automated remediation phase completed: {success_count}/{self.remediation_steps} steps executed successfully.")
        return self.passed_checks == 1
