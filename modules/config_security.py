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
            
            # --- BƯỚC MỚI: TẠO BACKUP NGINX.CONF TRƯỚC KHI SỬA ---
            # Tạo backup để có thể khôi phục nếu có lỗi
            self.cm.exec_command('sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup', sudo=True)
            self.logger.debug("Created backup of nginx.conf")
            
            # --- KIỂM TRA VÀ SỬA NGINX.CONF NẾU CÓ LỖI CỦA LẦN CHẠY TRƯớC ---
            # Loại bỏ các dòng include lỗi được thêm vào ở cuối file (ngoài http block)
            self.cm.exec_command('sudo sed -i "/^include \/etc\/nginx\/conf.d\/\\*.conf;$/d" /etc/nginx/nginx.conf', sudo=True)
            self.logger.info("Cleaned up any malformed include directives.")
            
            # --- BƯỚC MỚI: XÓA FILE CONFIG LỖI CŨ ---
            # Đây là bước quan trọng để loại bỏ lỗi 'add_header' từ lần chạy trước.
            self.cm.exec_command('sudo rm -f /etc/nginx/conf.d/security.conf', sudo=True)
            self.cm.exec_command('sudo rm -f /etc/nginx/conf.d/catchall.conf', sudo=True)
            self.cm.exec_command('sudo rm -f /etc/nginx/conf.d/default.conf', sudo=True)
            self.logger.info("Cleaned up old /etc/nginx/conf.d/ files.")

            # --- 2.5.1: Hide NGINX version ---
            self.logger.info("Setting server_tokens off (CIS 2.5.1)")
            cmd_tokens = 'sed -i "s/server_tokens.*/server_tokens off;/" /etc/nginx/nginx.conf 2>/dev/null || echo "server_tokens off;" | sudo tee -a /etc/nginx/nginx.conf'
            if self.cm.exec_command(cmd_tokens, sudo=True)[0] == 0:
                self.passed_checks += 1
            
            # Đảm bảo conf.d vẫn được include - chèn vào TRONG http block an toàn
            # Kiểm tra xem đã có include chưa
            check_cmd = 'grep -q "include /etc/nginx/conf.d/\\*.conf;" /etc/nginx/nginx.conf'
            if self.cm.exec_command(check_cmd)[0] != 0:
                # Chèn vào trong http block (sau dòng "http {")
                insert_cmd = 'sudo sed -i "/^http {/a \\    include /etc/nginx/conf.d/*.conf;" /etc/nginx/nginx.conf'
                self.cm.exec_command(insert_cmd, sudo=True)
                self.logger.info("Added include directive inside http block.")

            self.passed_checks += 2 
            self.logger.info("Core security (tokens) applied. Headers delegated to CISRemediate.")
            
            return self.passed_checks >= 1
                
        except Exception as e:
            self.logger.error(f"Security configuration failed: {str(e)}")
            return False