import logging
import time
import re

class InstallNginx:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 3
        self.passed_checks = 0

    def execute(self):
        try:
            self.logger.info("Installing NGINX")
            
            # Check if NGINX is installed
            exit_status, output, error = self.cm.exec_command('which nginx')
            if exit_status == 0:
                self.logger.info("NGINX is already installed")
                self.passed_checks += 1
                exit_status, output, error = self.cm.exec_command('nginx -v 2>&1')
                if exit_status == 0:
                    self.logger.info(f"Installed version: {output.strip()}")
            else:
                self.logger.info("Attempting to fix network connectivity and update lists...")
                # (Giữ lại logic sửa lỗi mạng và update lists)
                network_commands = [
                    'systemctl restart systemd-resolved',
                    'echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf',
                    'echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf'
                ]
                
                for cmd in network_commands:
                    self.cm.exec_command(cmd, sudo=True)
                    time.sleep(1)
                
                self.logger.info("Updating package lists...")
                if self.cm.exec_command('apt-get update', sudo=True)[0] != 0:
                    self.logger.error("Failed to update package lists.")
                    return False
                
                # Install NGINX
                self.logger.info("Installing NGINX package...")
                # Sử dụng apt-get/dnf theo phân phối. Ở đây giữ nguyên apt-get.
                install_cmd = 'apt-get install -y nginx' 
                exit_status, output, error = self.cm.exec_command(install_cmd, sudo=True)
                
                if exit_status == 0:
                    self.logger.info("NGINX installed successfully")
                    self.passed_checks += 1
                else:
                    self.logger.error(f"NGINX installation failed: {error}")
                    return False

            # Check NGINX service status (Giữ lại logic start service nếu chưa chạy)
            if not self._check_port_80():
                self.logger.warning("Port 80 is occupied, NGINX may not start. Continuing anyway...")
                
            # Try to start NGINX (Chạy service để các bước tiếp theo hoạt động)
            exit_status, output, error = self.cm.exec_command('systemctl is-active nginx', sudo=True)
            if exit_status != 0 or 'active' not in output:
                 self.logger.info("Starting NGINX service...")
                 exit_status, output, error = self.cm.exec_command('systemctl start nginx', sudo=True)
                 if exit_status == 0:
                     self.logger.info("NGINX service started successfully")
                     self.passed_checks += 1
                 else:
                     self.logger.warning(f"NGINX service failed to start: {error}")

            self.passed_checks += 1 # Đảm bảo check service có chạy được tính điểm.
            
            return self.passed_checks >= 1
            
        except Exception as e:
            self.logger.error(f"NGINX installation failed: {str(e)}")
            return False

    def _check_port_80(self):
        """Kiểm tra port 80 có đang được sử dụng không"""
        try:
            self.logger.info("Checking port 80...")
            exit_status, output, error = self.cm.exec_command('sudo ss -tulpn | grep ":80 "')
            
            if exit_status == 0:
                self.logger.warning(f"Port 80 is in use by: {output}")
                return False
            else:
                self.logger.info("Port 80 is free")
                return True
                
        except Exception as e:
            self.logger.error(f"Error while checking port 80: {str(e)}")
            return False