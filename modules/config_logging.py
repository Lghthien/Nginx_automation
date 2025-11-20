import logging
import base64

class ConfigLogging:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 2
        self.passed_checks = 0

    def execute(self):
        try:
            self.logger.info("Configuring logging settings (CIS 3.3, 3.4)")
            
            # --- 3.3 Ensure error logging is enabled and set to info level ---
            self.logger.info("Setting error_log to info level (CIS 3.3)")
            
            # 1. Xóa các dòng error_log cũ (FIX: Đảm bảo không còn dòng cũ)
            self.cm.exec_command("sudo sed -i '/error_log/d' /etc/nginx/nginx.conf", sudo=True) 
            
            # 2. Chèn dòng mới an toàn vào khối HTTP (FIX: Sửa lỗi cú pháp NGINX)
            # Chèn sau dòng 'http {'
            cmd_insert_error_log = "sudo sed -i '/http {/a error_log /var/log/nginx/error.log info;' /etc/nginx/nginx.conf"
            
            if self.cm.exec_command(cmd_insert_error_log, sudo=True)[0] == 0:
                 self.passed_checks += 1
                 self.logger.info("Error log set to info.")
            
            # --- 3.4 Ensure log files are rotated ---
            self.logger.info("Configuring log rotation (CIS 3.4)")
            logrotate_config = """/var/log/nginx/*.log {
    weekly
    missingok
    rotate 13
    compress
    delaycompress
    notifempty
    create 640 nginx adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 `cat /var/run/nginx.pid`
        fi
    endscript
}
"""
            config_b64 = logrotate_config.encode('utf-8')
            config_b64 = base64.b64encode(config_b64).decode('utf-8')

            cmd_logrotate = f'echo "{config_b64}" | base64 -d | sudo tee /etc/logrotate.d/nginx'
            
            if self.cm.exec_command(cmd_logrotate, sudo=True)[0] == 0:
                self.passed_checks += 1
                self.logger.info("Log rotation configured for weekly/13 weeks.")
            else:
                 self.logger.warning("Failed to write logrotate configuration.")

            # Đảm bảo quyền cho thư mục log
            self.cm.exec_command('sudo mkdir -p /var/log/nginx && sudo chown -R nginx:nginx /var/log/nginx', sudo=True)
            
            return self.passed_checks >= 1
                
        except Exception as e:
            self.logger.error(f"Logging configuration failed: {str(e)}")
            return False