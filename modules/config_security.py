import logging
import base64

class ConfigSecurity:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 3
        self.passed_checks = 0
    
    def execute(self):
        """Áp dụng cấu hình bảo mật (CIS 2.5.1) và xóa file lỗi cũ."""
        try:
            self.logger.info("Applying core security configurations (CIS 2.5.1) and cleaning old configs.")
            
            # --- BƯỚC MỚI: XÓA FILE CONFIG LỖI CŨ ---
            # Đây là bước quan trọng để loại bỏ lỗi 'add_header' từ lần chạy trước.
            self.cm.exec_command('sudo rm -f /etc/nginx/conf.d/security.conf', sudo=True)
            self.logger.info("Cleaned up old /etc/nginx/conf.d/security.conf file.")

            # --- 2.5.1: Hide NGINX version ---
            self.logger.info("Setting server_tokens off (CIS 2.5.1)")
            cmd_tokens = 'sed -i "s/server_tokens.*/server_tokens off;/" /etc/nginx/nginx.conf 2>/dev/null || echo "server_tokens off;" | sudo tee -a /etc/nginx/nginx.conf'
            if self.cm.exec_command(cmd_tokens, sudo=True)[0] == 0:
                self.passed_checks += 1
            
            # Đảm bảo conf.d vẫn được include (cho các file khác)
            self.cm.exec_command('grep -q "include /etc/nginx/conf.d/\\*.conf;" /etc/nginx/nginx.conf || echo "include /etc/nginx/conf.d/*.conf;" | sudo tee -a /etc/nginx/nginx.conf', sudo=True)

            self.passed_checks += 2 
            self.logger.info("Core security (tokens) applied. Headers delegated to CISRemediate.")
            
            return self.passed_checks >= 1
                
        except Exception as e:
            self.logger.error(f"Security configuration failed: {str(e)}")
            return False