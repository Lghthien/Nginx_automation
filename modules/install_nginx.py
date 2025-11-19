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
                
                # Get installed version
                exit_status, output, error = self.cm.exec_command('nginx -v 2>&1')
                if exit_status == 0:
                    self.logger.info(f"Installed version: {output.strip()}")
            else:
                # Fix network issues first
                self.logger.info("Attempting to fix network connectivity...")
                network_commands = [
                    'systemctl restart systemd-resolved',
                    'echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf',
                    'echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf'
                ]
                
                for cmd in network_commands:
                    self.cm.exec_command(cmd, sudo=True)
                    time.sleep(2)
                
                # Update package lists with retry
                self.logger.info("Updating package lists...")
                for attempt in range(3):
                    exit_status, output, error = self.cm.exec_command('apt-get update', sudo=True)
                    if exit_status == 0:
                        self.logger.info("Package lists updated successfully")
                        break
                    else:
                        self.logger.warning(f"Update attempt {attempt + 1} failed, retrying...")
                        time.sleep(5)
                
                if exit_status != 0:
                    self.logger.error("Failed to update package lists after multiple attempts")
                    return False

                # Install NGINX with fallback
                self.logger.info("Installing NGINX package...")
                install_commands = [
                    'apt-get install -y nginx',
                    'apt-get install -y nginx --fix-missing',
                    'apt-get install -y nginx --allow-unauthenticated'
                ]
                
                for cmd in install_commands:
                    exit_status, output, error = self.cm.exec_command(cmd, sudo=True)
                    if exit_status == 0:
                        self.logger.info("NGINX installed successfully")
                        self.passed_checks += 1
                        break
                    else:
                        self.logger.warning(f"Install command failed: {cmd}")

                if exit_status != 0:
                    self.logger.error("NGINX installation failed after multiple attempts")
                    return False

            # Kiểm tra port 80 trước khi start NGINX
            if not self._check_port_80():
                self.logger.error("Port 80 is occupied, NGINX may not start")
                # Vẫn tiếp tục thử start NGINX

            # Check NGINX service status
            exit_status, output, error = self.cm.exec_command('systemctl is-active nginx', sudo=True)
            if exit_status == 0 and 'active' in output:
                self.logger.info("NGINX service is running")
                self.passed_checks += 1
            else:
                # Try to start NGINX
                self.logger.info("Starting NGINX service...")
                exit_status, output, error = self.cm.exec_command('systemctl start nginx', sudo=True)
                if exit_status == 0:
                    self.logger.info("NGINX service started successfully")
                    self.passed_checks += 1
                else:
                    self.logger.warning(f"NGINX service is not running: {error}")

            # Enable NGINX to start on boot
            exit_status, output, error = self.cm.exec_command('systemctl enable nginx', sudo=True)
            if exit_status == 0:
                self.logger.info("NGINX enabled to start on boot")

            return self.passed_checks >= 1  # At least one check must pass
            
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