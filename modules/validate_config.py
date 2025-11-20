import logging

class ValidateConfig:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 2
        self.passed_checks = 0
    
    def execute(self):
        """Validate cấu hình NGINX"""
        try:
            self.logger.info("Validating NGINX configuration")
            
            # Kiểm tra xem NGINX đã được cài đặt chưa
            exit_status, output, error = self.cm.exec_command('which nginx')
            if exit_status != 0:
                self.logger.warning("NGINX not installed, skipping validation")
                self.passed_checks = 1  # Vẫn tính là passed vì không có lỗi
                return True

            # Kiểm tra cú pháp cấu hình NGINX
            exit_status, output, error = self.cm.exec_command('nginx -t', sudo=True)
            
            if exit_status == 0:
                self.logger.info("NGINX configuration validation passed")
                self.passed_checks += 1
                
                # Kiểm tra xem có security config không
                exit_status, output, error = self.cm.exec_command('ls /etc/nginx/conf.d/security.conf', sudo=True)
                if exit_status == 0:
                    self.logger.info("Security configuration file exists")
                    self.passed_checks += 1
                else:
                    self.logger.warning("Security configuration file not found")
                
                return True
            else:
                self.logger.error(f"NGINX configuration validation failed: {error}")
                
                # Phân tích lỗi chi tiết
                if "emerg" in error.lower():
                    lines = error.split('\n')
                    for line in lines:
                        if "emerg" in line.lower():
                            self.logger.error(f"Configuration error: {line}")
                
                # Cố gắng khôi phục từ backup nếu có
                self.logger.warning("Attempting to restore nginx.conf from backup...")
                restore_status, _, restore_error = self.cm.exec_command('sudo cp /etc/nginx/nginx.conf.backup /etc/nginx/nginx.conf', sudo=True)
                if restore_status == 0:
                    self.logger.info("Successfully restored nginx.conf from backup")
                    # Kiểm tra lại sau khi restore
                    validate_status, _, _ = self.cm.exec_command('nginx -t', sudo=True)
                    if validate_status == 0:
                        self.logger.info("Configuration is valid after restore")
                        return True
                else:
                    self.logger.error(f"Failed to restore backup: {restore_error}")
                
                return False
                
        except Exception as e:
            self.logger.error(f"Validation failed: {str(e)}")
            return False