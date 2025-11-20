import logging
from typing import Tuple
import re

class CISRemediate:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 1 
        self.passed_checks = 0
        self.nginx_dir = "/etc/nginx"
        self.nginx_conf_path = "/etc/nginx/nginx.conf"
        # File default server để chỉnh sửa header
        self.default_conf_path = "/etc/nginx/conf.d/default.conf" 

    def run_command(self, cmd: str, sudo: bool = True) -> Tuple[int, str, str]:
        try:
            exit_status, stdout, stderr = self.cm.exec_command(cmd, sudo=sudo)
            return exit_status, stdout, stderr
        except:
            return 1, "", "Error during command execution"

    def _add_security_headers(self):
        """Khắc phục CIS 5.3.1 và 5.3.2 bằng cách thêm header vào khối server"""
        # Header X-Frame-Options (5.3.1) và X-Content-Type-Options (5.3.2)
        headers = [
            'add_header X-Frame-Options "SAMEORIGIN" always;',
            'add_header X-Content-Type-Options "nosniff" always;'
        ]
        
        for header in headers:
            # Chèn header vào khối 'server {' đầu tiên
            cmd = f"sudo sed -i '/server {{/a \\    {header}' {self.default_conf_path} 2>/dev/null || sudo sed -i '/http {{/a \\    {header}' {self.nginx_conf_path} "
            # Sử dụng sed để chèn vào khối server đầu tiên trong default.conf
            self.run_command(f"sudo sed -i '/server {{/a \\    {header}' {self.default_conf_path}", sudo=True) 
        self.logger.info("Applied security headers directly into default server block.")

    def _remediate_2_4_3_keepalive_timeout(self):
        # 2.4.3 Ensure keepalive_timeout is 10 seconds or less
        cmd = f"sudo sed -i '/keepalive_timeout/d' {self.nginx_conf_path} && sudo sed -i '/http {{/a \\    keepalive_timeout 10;' {self.nginx_conf_path}"
        self.run_command(cmd)

    def _remediate_2_4_4_send_timeout(self):
        # 2.4.4 Ensure send_timeout is set to 10 seconds or less
        cmd = f"sudo sed -i '/send_timeout/d' {self.nginx_conf_path} && sudo sed -i '/http {{/a \\    send_timeout 10;' {self.nginx_conf_path}"
        self.run_command(cmd)
        
    def _remediate_2_2_2_user_lock(self):
        # 2.2.2 Ensure the NGINX service account is locked
        self.run_command("passwd -l nginx")
    
    # ... (CÁC HÀM KHẮC PHỤC KHÁC)

    def execute(self):
        self.logger.info("Applying full CIS NGINX Automated Remediation")
        
        remediations = [
            self._add_security_headers,          # Khắc phục lỗi cấu hình Header
            self._remediate_2_4_3_keepalive_timeout, 
            self._remediate_2_4_4_send_timeout,      
            self._remediate_2_2_2_user_lock,
            # ... (Thêm các hàm khắc phục khác)
        ]
        
        success_count = 0
        for remediation in remediations:
            try:
                remediation()
                success_count += 1
            except Exception as e:
                self.logger.error(f"Remediation failed for {remediation.__name__}: {e}")

        self.passed_checks = 1 if success_count == len(remediations) else 0
        self.logger.info(f"Automated remediation phase completed: {success_count}/{len(remediations)} steps executed successfully.")
        return self.passed_checks == 1