import logging
from typing import Tuple
import re
import os
import datetime

# Class này được đặt tên là CISRemediate để phù hợp với các module khác
class CISRemediate:
    def __init__(self, connection_manager, logger, nginx_conf_path: str = "/etc/nginx/nginx.conf"):
        self.cm = connection_manager
        self.logger = logger
        self.nginx_conf_path = nginx_conf_path
        self.nginx_dir = "/etc/nginx"
        self.backup_dir = "/root/nginx_cis_backup"
        self.check_count = 1  # Chỉ tính là 1 bước khắc phục tổng thể
        self.passed_checks = 0

    def run_command(self, cmd: str, sudo: bool = True) -> Tuple[int, str, str]:
        """Thực thi lệnh shell sử dụng connection manager (mặc định là sudo)"""
        try:
            exit_status, stdout, stderr = self.cm.exec_command(cmd, sudo=sudo)
            return exit_status, stdout, stderr
        except Exception as e:
            self.logger.error(f"Lỗi thực thi lệnh: {e}")
            return 1, "", str(e)
    
    def create_backup(self):
        """Tạo bản sao lưu cấu hình NGINX trước khi khắc phục"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{self.backup_dir}/nginx_conf_{timestamp}"
        
        self.logger.info(f"Tạo bản sao lưu tại: {backup_path}")
        # Dùng lệnh mkdir -p và cp -r qua connection manager
        self.run_command(f"mkdir -p {self.backup_dir}")
        self.run_command(f"cp -r {self.nginx_dir} {backup_path}")

    def test_nginx_config(self) -> bool:
        """Kiểm tra cú pháp cấu hình NGINX"""
        self.logger.info("Kiểm tra cấu hình NGINX...")
        rc, stdout, stderr = self.run_command("nginx -t", sudo=True)
        
        if rc == 0:
            self.logger.info("Kiểm tra cấu hình NGINX thành công")
            return True
        else:
            self.logger.error(f"Kiểm tra cấu hình NGINX thất bại: {stderr}")
            return False

    def reload_nginx(self):
        """Reload NGINX"""
        self.logger.info("Reloading NGINX...")
        rc, _, _ = self.run_command("systemctl reload nginx", sudo=True)
        if rc != 0:
            self.logger.warning("Reload thất bại, thử restart...")
            self.run_command("systemctl restart nginx", sudo=True)

    # Các phương thức khắc phục CIS (chỉ giữ lại 3 ví dụ)
    
    def _remediate_server_tokens(self):
        """2.5.1 Ẩn server tokens"""
        self.logger.info("Khắc phục 2.5.1: Ẩn server tokens")
        self.add_or_update_directive("server_tokens", "off")
    
    def _remediate_keepalive_timeout(self):
        """2.4.3 Đặt keepalive timeout"""
        self.logger.info("Khắc phục 2.4.3: Đặt keepalive timeout")
        self.add_or_update_directive("keepalive_timeout", "10")
        
    def _remediate_x_frame_options(self):
        """5.3.1 Cấu hình X-Frame-Options"""
        self.logger.info("Khắc phục 5.3.1: Cấu hình X-Frame-Options")
        header = 'add_header X-Frame-Options "SAMEORIGIN" always;'
        self.add_to_server_block(header)

    # THÊM CÁC PHƯƠNG THỨC KHẮC PHỤC KHÁC (remediate_autoindex, remediate_nginx_user, v.v.) TỪ MÃ MẪU

    def add_or_update_directive(self, directive: str, value: str):
        """Thêm hoặc cập nhật một chỉ thị trong nginx.conf (thực hiện thông qua sed)"""
        # Đây là một giải pháp đơn giản hơn thay vì đọc và viết lại file trong Python
        cmd_update = f"sudo sed -i '/^\\s*{directive}\\s+/c\\{directive} {value};' {self.nginx_conf_path}"
        cmd_add = f"sudo grep -q '{directive}' {self.nginx_conf_path} || sudo sed -i '/http {{/a \\    {directive} {value};' {self.nginx_conf_path}"
        
        self.run_command(cmd_update, sudo=True) # Thử cập nhật
        self.run_command(cmd_add, sudo=True)    # Thử thêm vào khối http nếu chưa có

    def add_to_server_block(self, config: str):
        """Thêm cấu hình vào khối server (thực hiện thông qua sed)"""
        # Thêm vào đầu khối server đầu tiên
        cmd = f"sudo sed -i '/server {{/a \\    {config}' {self.nginx_conf_path}"
        self.run_command(cmd, sudo=True)

    def execute(self) -> bool:
        """Thực thi toàn bộ các bước khắc phục CIS"""
        try:
            self.logger.info("Applying CIS NGINX Benchmark Remediation")
            
            self.create_backup()
            
            remediations = [
                self._remediate_server_tokens,
                self._remediate_keepalive_timeout,
                self._remediate_x_frame_options,
                # THÊM CÁC PHƯƠNG THỨC KHẮC PHỤC KHÁC TẠI ĐÂY
            ]
            
            success = True
            for remediation in remediations:
                try:
                    remediation()
                except Exception as e:
                    self.logger.error(f"Lỗi trong khắc phục {remediation.__name__}: {e}")
                    success = False
            
            # Kiểm tra và reload NGINX
            if self.test_nginx_config():
                self.reload_nginx()
                self.logger.info("Khắc phục hoàn tất thành công")
                self.passed_checks = 1
                return True
            else:
                self.logger.error("Khắc phục hoàn tất nhưng kiểm tra cấu hình thất bại. Vui lòng kiểm tra thủ công.")
                return False
                
        except Exception as e:
            self.logger.error(f"Khắc phục CIS thất bại: {str(e)}")
            return False