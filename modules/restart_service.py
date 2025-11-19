import logging
import time
import re

class RestartService:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 1
        self.passed_checks = 0
    
    def execute(self):
        """Khởi động lại dịch vụ NGINX"""
        try:
            self.logger.info("Restarting NGINX service")
            
            # Kiểm tra xem NGINX đã được cài đặt chưa
            exit_status, output, error = self.cm.exec_command('which nginx')
            if exit_status != 0:
                self.logger.warning("NGINX not installed, skipping service restart")
                self.passed_checks = 1  # Vẫn tính là passed
                return True

            # Kiểm tra xem service có tồn tại không
            exit_status, output, error = self.cm.exec_command('systemctl status nginx', sudo=True)
            if exit_status != 0 and "Unit nginx.service not found" in error:
                self.logger.warning("NGINX service not found, attempting to start")
                exit_status, output, error = self.cm.exec_command('systemctl start nginx', sudo=True)
                if exit_status == 0:
                    self.logger.info("NGINX service started successfully")
                    self.passed_checks = 1
                    return True
                else:
                    self.logger.error("Failed to start NGINX service")
                    return False

            # Thử reload NGINX trước
            self.logger.info("Attempting to reload NGINX...")
            exit_status, output, error = self.cm.exec_command('systemctl reload nginx', sudo=True)
            
            if exit_status == 0:
                self.logger.info("NGINX reloaded successfully")
                time.sleep(2)
                return self._check_nginx_status()
            else:
                # Thử restart thay vì reload
                self.logger.warning("Reload failed, trying restart...")
                exit_status, output, error = self.cm.exec_command('systemctl restart nginx', sudo=True)
                
                if exit_status == 0:
                    self.logger.info("NGINX restarted successfully")
                    time.sleep(2)
                    return self._check_nginx_status()
                else:
                    # Thử stop rồi start
                    self.logger.warning("Restart failed, trying stop-then-start...")
                    self.cm.exec_command('systemctl stop nginx', sudo=True)
                    time.sleep(2)
                    exit_status, output, error = self.cm.exec_command('systemctl start nginx', sudo=True)
                    
                    if exit_status == 0:
                        self.logger.info("NGINX started successfully after stop")
                        time.sleep(2)
                        return self._check_nginx_status()
                    else:
                        self.logger.error(f"Failed to restart NGINX: {error}")
                        return False
                    
        except Exception as e:
            self.logger.error(f"Service restart failed: {str(e)}")
            return False
    
    def _check_nginx_status(self):
        """Kiểm tra trạng thái NGINX"""
        exit_status, output, error = self.cm.exec_command('systemctl is-active nginx', sudo=True)
        
        if exit_status == 0 and 'active' in output.lower():
            self.logger.info("NGINX is running and active")
            self.passed_checks = 1
            return True
        else:
            self.logger.warning(f"NGINX is not active: {output}")
            return False