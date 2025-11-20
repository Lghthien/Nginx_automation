import logging
import base64

class ConfigSecurity:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 3
        self.passed_checks = 0
    
    def execute(self):
        """Áp dụng cấu hình bảo mật cơ bản cho NGINX (CIS 2.5.1, 5.3.1, 5.3.2)"""
        try:
            self.logger.info("Applying core security configurations (CIS 2.5.1, 5.3.1, 5.3.2)")
            
            # --- 2.5.1: Hide NGINX version ---
            self.logger.info("Setting server_tokens off (CIS 2.5.1)")
            cmd_tokens = 'sed -i "s/server_tokens.*/server_tokens off;/" /etc/nginx/nginx.conf 2>/dev/null || echo "server_tokens off;" | sudo tee -a /etc/nginx/nginx.conf'
            if self.cm.exec_command(cmd_tokens, sudo=True)[0] == 0:
                self.passed_checks += 1

            # --- Tạo file security.conf cho headers ---
            security_config = """# Security Headers Configuration
# CIS 5.3.1: Mitigate clickjacking attacks
add_header X-Frame-Options "SAMEORIGIN" always;

# CIS 5.3.2: Prevent MIME-type sniffing
add_header X-Content-Type-Options "nosniff" always;
"""
            security_config_b64 = base64.b64encode(security_config.encode()).decode()
            
            commands = [
                'mkdir -p /etc/nginx/conf.d',
                f'echo {security_config_b64} | base64 -d | sudo tee /etc/nginx/conf.d/security.conf',
                # Đảm bảo nginx.conf include conf.d
                'grep -q "include /etc/nginx/conf.d/\\*.conf;" /etc/nginx/nginx.conf || echo "include /etc/nginx/conf.d/*.conf;" | sudo tee -a /etc/nginx/nginx.conf',
            ]
            
            success_count = 0
            for cmd in commands:
                if self.cm.exec_command(cmd, sudo=True)[0] == 0:
                    success_count += 1
            
            if success_count >= 2:
                self.logger.info("Security headers applied successfully.")
                self.passed_checks += 2
            
            return self.passed_checks >= 1
                
        except Exception as e:
            self.logger.error(f"Security configuration failed: {str(e)}")
            return False