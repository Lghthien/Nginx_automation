import logging

class ConfigLogging:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 2
        self.passed_checks = 0

    def execute(self):
        try:
            self.logger.info("Configuring logging settings")
            
            # Tạo log directory nếu chưa tồn tại
            commands = [
                'sudo mkdir -p /var/log/nginx',
                'sudo touch /var/log/nginx/access.log',
                'sudo touch /var/log/nginx/error.log',
                'sudo chown -R nginx:nginx /var/log/nginx 2>/dev/null || sudo chown -R www-data:www-data /var/log/nginx 2>/dev/null || echo "Cannot change ownership, continuing..."'
            ]
            
            success_count = 0
            for cmd in commands:
                exit_status, output, error = self.cm.exec_command(cmd, sudo=True)
                if exit_status == 0 or "Cannot change ownership" in error:
                    success_count += 1
                    self.logger.info(f"Logging command successful: {cmd}")
                else:
                    self.logger.warning(f"Logging command failed: {cmd}, Error: {error}")
            
            self.passed_checks = success_count
            
            if success_count >= 2:
                self.logger.info("Logging configuration completed")
                return True
            else:
                self.logger.warning("Logging configuration completed with warnings")
                return True  # Vẫn trả về True vì không phải lỗi nghiêm trọng
                
        except Exception as e:
            self.logger.error(f"Logging configuration failed: {str(e)}")
            return False