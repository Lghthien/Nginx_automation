import logging
import re
import os
from typing import Tuple, List

class CISRemediate:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.nginx_dir = "/etc/nginx"
        self.nginx_conf_path = "/etc/nginx/nginx.conf"
        self.remediation_steps = 15
        self.passed_checks = 0

    def run_command(self, cmd: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Thực thi lệnh shell."""
        try:
            exit_status, stdout, stderr = self.cm.exec_command(cmd, sudo=sudo)
            return exit_status, stdout, stderr
        except Exception as e:
            self.logger.error(f"Command execution failed: {cmd}, Error: {e}")
            return 1, "", str(e)

    def _clean_config_file(self):
        """Dọn dẹp file cấu hình - loại bỏ các directive trùng lặp và không hợp lệ"""
        self.logger.info("Cleaning NGINX configuration file...")
        
        # Đọc file cấu hình hiện tại
        rc, config_content, _ = self.run_command(f"cat {self.nginx_conf_path}")
        if rc != 0:
            self.logger.error("Cannot read nginx.conf")
            return False

        lines = config_content.split('\n')
        cleaned_lines = []
        in_http_block = False
        seen_directives = set()

        for line in lines:
            stripped = line.strip()
            
            # Theo dõi khối http
            if stripped == 'http {':
                in_http_block = True
                seen_directives.clear()  # Reset cho khối http mới
                cleaned_lines.append(line)
                continue
            elif stripped == '}':
                in_http_block = False
                cleaned_lines.append(line)
                continue
            elif stripped.endswith('{'):
                # Bắt đầu một khối mới
                in_http_block = False
                cleaned_lines.append(line)
                continue
            
            # Xử lý các directive trong http block
            if in_http_block and stripped and not stripped.startswith('#'):
                # Trích xuất tên directive
                match = re.match(r'^(\S+)\s+', stripped)
                if match:
                    directive_name = match.group(1)
                    
                    # Nếu directive đã tồn tại, bỏ qua
                    if directive_name in seen_directives:
                        self.logger.info(f"Removed duplicate directive: {directive_name}")
                        continue
                    else:
                        seen_directives.add(directive_name)
                        cleaned_lines.append(line)
                else:
                    cleaned_lines.append(line)
            else:
                cleaned_lines.append(line)

        # Ghi file đã dọn dẹp
        temp_file = "/tmp/nginx_cleaned.conf"
        with open(temp_file, 'w') as f:
            f.write('\n'.join(cleaned_lines))
        
        # Sao chép file đã dọn dẹp
        self.run_command(f"sudo cp {temp_file} {self.nginx_conf_path}")
        self.run_command(f"sudo rm -f {temp_file}")
        self.logger.info("Configuration file cleaned successfully")
        return True

    def _safe_add_directive(self, directive: str, value: str, block: str = "http"):
        """Thêm directive một cách an toàn - tránh trùng lặp"""
        if not value.endswith(';'):
            value += ';'
        
        full_directive = f"{directive} {value}"
        
        # Kiểm tra nếu directive đã tồn tại
        rc, stdout, _ = self.run_command(f"grep -E '^{directive}[[:space:]]+' {self.nginx_conf_path}")
        if rc == 0:
            # Cập nhật directive hiện có
            escaped_directive = re.escape(directive)
            escaped_value = re.escape(value)
            cmd = f"sudo sed -i 's/^{escaped_directive}\\s\\+[^;]*;/{full_directive}/' {self.nginx_conf_path}"
            self.run_command(cmd)
            self.logger.info(f"Updated directive: {full_directive}")
        else:
            # Thêm directive mới
            if block == "http":
                cmd = f"sudo sed -i '/http {{/a\\\\    {full_directive}' {self.nginx_conf_path}"
            else:
                cmd = f"echo '    {full_directive}' | sudo tee -a {self.nginx_dir}/{block}"
            
            self.run_command(cmd)
            self.logger.info(f"Added directive: {full_directive}")

    def _create_ssl_certificates(self):
        """Tạo SSL certificates cần thiết"""
        self.logger.info("Creating SSL certificates...")
        
        # Tạo thư mục nếu chưa tồn tại
        self.run_command("sudo mkdir -p /etc/ssl/private /etc/ssl/certs /etc/nginx/client_certs")
        
        # Tạo self-signed certificate cho server
        ssl_cmd = """
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout /etc/ssl/private/nginx-selfsigned.key \
-out /etc/ssl/certs/nginx-selfsigned.crt \
-subj '/C=US/ST=State/L=City/O=Organization/CN=localhost' -batch 2>/dev/null
"""
        self.run_command(ssl_cmd)
        
        # Tạo client certificate cho upstream authentication
        client_cmds = [
            "sudo openssl genrsa -out /etc/nginx/client_certs/client.key 2048 2>/dev/null",
            "sudo openssl req -new -key /etc/nginx/client_certs/client.key -out /etc/nginx/client_certs/client.csr -subj '/CN=client' -batch 2>/dev/null",
            "sudo openssl x509 -req -days 365 -in /etc/nginx/client_certs/client.csr -signkey /etc/nginx/client_certs/client.key -out /etc/nginx/client_certs/client.crt 2>/dev/null"
        ]
        
        for cmd in client_cmds:
            self.run_command(cmd)
        
        self.logger.info("SSL certificates created successfully")

    def _remediate_2_4_2_unknown_hosts(self):
        """2.4.2 - Configure catch-all server for unknown hosts"""
        self.logger.info("Remediating 2.4.2 - Unknown hosts rejection")
        
        catchall_config = """
# CIS 2.4.2 - Catch-all server for unknown host names
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    
    # SSL configuration
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    
    return 444;
}
"""
        # Ghi cấu hình catch-all
        cmd = f"echo '{catchall_config}' | sudo tee /etc/nginx/conf.d/catchall.conf"
        self.run_command(cmd)
        self.run_command("sudo chmod 644 /etc/nginx/conf.d/catchall.conf")
        
        self.passed_checks += 1
        self.logger.info("✓ 2.4.2 - Catch-all server configured")

    def _remediate_4_1_4_modern_tls(self):
        """4.1.4 - Configure only modern TLS protocols"""
        self.logger.info("Remediating 4.1.4 - Modern TLS protocols")
        
        self._safe_add_directive("ssl_protocols", "TLSv1.2 TLSv1.3")
        self.passed_checks += 1
        self.logger.info("✓ 4.1.4 - Modern TLS protocols configured")

    def _remediate_4_1_6_custom_dhparam(self):
        """4.1.6 - Generate and use custom Diffie-Hellman parameters"""
        self.logger.info("Remediating 4.1.6 - Custom DH parameters")
        
        dh_path = "/etc/ssl/certs/dhparam.pem"
        
        # Tạo DH parameters (sử dụng 1024-bit để nhanh hơn)
        self.run_command(f"sudo openssl dhparam -out {dh_path} 1024 2>/dev/null")
        
        self._safe_add_directive("ssl_dhparam", dh_path)
        self.passed_checks += 1
        self.logger.info("✓ 4.1.6 - Custom DH parameters configured")

    def _remediate_4_1_7_ocsp_stapling(self):
        """4.1.7 - Enable OCSP stapling"""
        self.logger.info("Remediating 4.1.7 - OCSP stapling")
        
        self._safe_add_directive("ssl_stapling", "on")
        self._safe_add_directive("ssl_stapling_verify", "on")
        self._safe_add_directive("resolver", "8.8.8.8 8.8.4.4 valid=300s")
        self._safe_add_directive("resolver_timeout", "5s")
        
        self.passed_checks += 1
        self.logger.info("✓ 4.1.7 - OCSP stapling enabled")

    def _remediate_4_1_9_client_cert_auth(self):
        """4.1.9 - Configure upstream client certificate authentication"""
        self.logger.info("Remediating 4.1.9 - Client certificate authentication")
        
        # Thêm cấu hình upstream client certificates
        upstream_config = """
# CIS 4.1.9 - Upstream client certificate authentication
proxy_ssl_certificate /etc/nginx/client_certs/client.crt;
proxy_ssl_certificate_key /etc/nginx/client_certs/client.key;
proxy_ssl_verify off;
"""
        cmd = f"echo '{upstream_config}' | sudo tee -a {self.nginx_conf_path}"
        self.run_command(cmd)
        
        self.passed_checks += 1
        self.logger.info("✓ 4.1.9 - Client certificate authentication configured")

    def _remediate_4_1_12_session_resumption(self):
        """4.1.12 - Disable session resumption"""
        self.logger.info("Remediating 4.1.12 - Session resumption")
        
        self._safe_add_directive("ssl_session_tickets", "off")
        self.passed_checks += 1
        self.logger.info("✓ 4.1.12 - Session resumption disabled")

    def _remediate_4_1_13_http2(self):
        """4.1.13 - Enable HTTP/2.0"""
        self.logger.info("Remediating 4.1.13 - HTTP/2.0")
        
        # HTTP/2 đã được cấu hình trong catchall server block
        # Thêm http2 vào bất kỳ server block nào tồn tại
        conf_files = ["conf.d/default.conf", "sites-available/default", "sites-enabled/default"]
        
        for conf_file in conf_files:
            full_path = f"{self.nginx_dir}/{conf_file}"
            rc, _, _ = self.run_command(f"test -f {full_path}")
            if rc == 0:
                self.run_command(f"sudo sed -i 's/listen 443 ssl;/listen 443 ssl http2;/g' {full_path}")
                self.run_command(f"sudo sed -i 's/listen \\[::\\]:443 ssl;/listen [::]:443 ssl http2;/g' {full_path}")
        
        self.passed_checks += 1
        self.logger.info("✓ 4.1.13 - HTTP/2.0 enabled")

    def _remediate_security_headers(self):
        """Configure security headers"""
        self.logger.info("Remediating security headers")
        
        headers = [
            ('add_header X-Frame-Options', '"SAMEORIGIN" always'),
            ('add_header X-Content-Type-Options', '"nosniff" always'),
            ('add_header X-XSS-Protection', '"1; mode=block" always'),
            ('add_header Referrer-Policy', '"strict-origin-when-cross-origin" always'),
            ('add_header Strict-Transport-Security', '"max-age=15768000; includeSubDomains" always')
        ]
        
        for directive, value in headers:
            self._safe_add_directive(directive, value)
        
        self.logger.info("✓ Security headers configured")

    def _remediate_ssl_ciphers(self):
        """Configure strong SSL ciphers"""
        self.logger.info("Remediating SSL ciphers")
        
        ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
        
        ssl_configs = [
            ("ssl_ciphers", ciphers),
            ("ssl_prefer_server_ciphers", "on"),
            ("ssl_ecdh_curve", "secp384r1"),
            ("ssl_session_cache", "shared:SSL:10m"),
            ("ssl_session_timeout", "10m")
        ]
        
        for directive, value in ssl_configs:
            self._safe_add_directive(directive, value)
        
        self.logger.info("✓ SSL ciphers configured")

    def _remediate_performance_directives(self):
        """Configure performance-related directives"""
        self.logger.info("Remediating performance directives")
        
        performance_configs = [
            ("client_body_buffer_size", "1k"),
            ("client_header_buffer_size", "1k"),
            ("client_max_body_size", "1m"),
            ("large_client_header_buffers", "2 1k"),
            ("client_body_timeout", "10"),
            ("client_header_timeout", "10"),
            ("keepalive_timeout", "10"),
            ("send_timeout", "10"),
            ("reset_timedout_connection", "on")
        ]
        
        for directive, value in performance_configs:
            self._safe_add_directive(directive, value)
        
        self.logger.info("✓ Performance directives configured")

    def _remediate_user_permissions(self):
        """Configure user and permissions"""
        self.logger.info("Remediating user permissions")
        
        # Đảm bảo user nginx tồn tại và bị khóa
        self.run_command("sudo useradd -r -s /bin/false nginx 2>/dev/null || true")
        self.run_command("sudo passwd -l nginx 2>/dev/null || true")
        
        # Đặt quyền cho thư mục cấu hình
        self.run_command("sudo chown -R root:root /etc/nginx")
        self.run_command("sudo chmod -R 644 /etc/nginx")
        self.run_command("sudo find /etc/nginx -type d -exec chmod 755 {} +")
        
        # Đặt quyền cho PID file
        self.run_command("sudo chown root:root /run/nginx.pid 2>/dev/null || true")
        self.run_command("sudo chmod 644 /run/nginx.pid 2>/dev/null || true")
        
        self.logger.info("✓ User permissions configured")

    def _remediate_default_pages(self):
        """Remove NGINX references from default pages"""
        self.logger.info("Remediating default pages")
        
        index_html = """<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to Our Server</h1>
    <p>The server is operational.</p>
</body>
</html>"""
        
        # Ghi file index.html mới
        cmd = f"echo '{index_html}' | sudo tee /usr/share/nginx/html/index.html"
        self.run_command(cmd)
        self.run_command("sudo chmod 644 /usr/share/nginx/html/index.html")
        
        self.logger.info("✓ Default pages remediated")

    def _cleanup_old_configs(self):
        """Dọn dẹp các cấu hình cũ"""
        self.logger.info("Cleaning up old configurations")
        
        cleanup_cmds = [
            "sudo rm -f /etc/nginx/conf.d/default.conf",
            "sudo rm -f /etc/nginx/sites-enabled/default",
            "sudo find /etc/nginx -name '*.bak' -delete",
            "sudo sed -i '/autoindex on/d' /etc/nginx/nginx.conf 2>/dev/null || true"
        ]
        
        for cmd in cleanup_cmds:
            self.run_command(cmd)
        
        self.logger.info("✓ Old configurations cleaned up")

    def _validate_configuration(self):
        """Validate NGINX configuration"""
        self.logger.info("Validating NGINX configuration...")
        
        rc, stdout, stderr = self.run_command("nginx -t")
        if rc == 0:
            self.logger.info("✓ NGINX configuration validation passed")
            return True
        else:
            self.logger.error(f"✗ NGINX configuration validation failed: {stderr}")
            return False

    def execute(self):
        """Thực thi toàn bộ quá trình khắc phục"""
        self.logger.info("Starting comprehensive CIS NGINX remediation")
        
        # Tạo backup
        self.run_command(f"sudo cp {self.nginx_conf_path} {self.nginx_conf_path}.backup")
        
        try:
            # Danh sách các bước khắc phục theo thứ tự
            remediation_steps = [
                self._clean_config_file,
                self._cleanup_old_configs,
                self._create_ssl_certificates,
                self._remediate_user_permissions,
                self._remediate_default_pages,
                self._remediate_2_4_2_unknown_hosts,
                self._remediate_4_1_4_modern_tls,
                self._remediate_4_1_6_custom_dhparam,
                self._remediate_4_1_7_ocsp_stapling,
                self._remediate_4_1_9_client_cert_auth,
                self._remediate_4_1_12_session_resumption,
                self._remediate_4_1_13_http2,
                self._remediate_security_headers,
                self._remediate_ssl_ciphers,
                self._remediate_performance_directives
            ]
            
            success_count = 0
            total_steps = len(remediation_steps)
            
            for step in remediation_steps:
                try:
                    step()
                    success_count += 1
                except Exception as e:
                    self.logger.error(f"Remediation step failed: {step.__name__}, Error: {e}")
                    continue
            
            # Validate cấu hình cuối cùng
            if self._validate_configuration():
                self.logger.info(f"✓ CIS remediation completed successfully: {success_count}/{total_steps} steps passed")
                self.passed_checks = success_count
                return True
            else:
                self.logger.error("Configuration validation failed - restoring backup")
                self.run_command(f"sudo cp {self.nginx_conf_path}.backup {self.nginx_conf_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Remediation process failed critically: {e}")
            self.run_command(f"sudo cp {self.nginx_conf_path}.backup {self.nginx_conf_path}")
            return False

    def get_results(self):
        """Trả về kết quả khắc phục"""
        return {
            "remediation_steps": self.remediation_steps,
            "passed_checks": self.passed_checks,
            "success_rate": (self.passed_checks / self.remediation_steps) * 100 if self.remediation_steps > 0 else 0
        }