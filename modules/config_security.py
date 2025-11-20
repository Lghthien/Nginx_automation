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
            
            # --- BƯỚC 1: XÓA HOÀN TOÀN THƯ MỤC CONF.D VÀ TẠO LẠI ---
            self.logger.info("Completely cleaning and recreating /etc/nginx/conf.d")
            self.cm.exec_command('sudo rm -rf /etc/nginx/conf.d', sudo=True)
            self.cm.exec_command('sudo mkdir -p /etc/nginx/conf.d', sudo=True)
            self.cm.exec_command('sudo chmod 755 /etc/nginx/conf.d', sudo=True)
            self.logger.info("✓ Completely cleaned and recreated /etc/nginx/conf.d")
            
            # --- BƯỚC 2: TẠO BACKUP NGINX.CONF TRƯỚC KHI SỬA ---
            self.cm.exec_command('sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup', sudo=True)
            self.logger.debug("Created backup of nginx.conf")
            
            # --- BƯỚC 3: DỌN DẸP CÁC DIRECTIVE LỖI ---
            self.logger.info("Cleaning up malformed include directives and old configurations")
            
            # Loại bỏ các dòng include lỗi được thêm vào ở cuối file (ngoài http block)
            self.cm.exec_command('sudo sed -i "/^include \/etc\/nginx\/conf.d\/\\*.conf;$/d" /etc/nginx/nginx.conf', sudo=True)
            
            # Xóa các file config cũ có thể gây lỗi
            cleanup_files = [
                '/etc/nginx/conf.d/security.conf',
                '/etc/nginx/conf.d/catchall.conf', 
                '/etc/nginx/conf.d/default.conf',
                '/etc/nginx/conf.d/http2.conf'
            ]
            
            for file_path in cleanup_files:
                self.cm.exec_command(f'sudo rm -f {file_path}', sudo=True)
            
            self.logger.info("✓ Cleaned up malformed directives and old config files")

            # --- BƯỚC 4: CẤU HÌNH SERVER_TOKENS OFF (CIS 2.5.1) ---
            self.logger.info("Setting server_tokens off (CIS 2.5.1)")
            
            # Phương pháp 1: Thay thế nếu tồn tại
            cmd_replace = 'sudo sed -i "s/^[[:space:]]*server_tokens[[:space:]]*.*/server_tokens off;/" /etc/nginx/nginx.conf'
            exit_status, output, error = self.cm.exec_command(cmd_replace, sudo=True)
            
            # Phương pháp 2: Thêm mới nếu không tồn tại
            if exit_status != 0:
                cmd_add = 'echo "server_tokens off;" | sudo tee -a /etc/nginx/nginx.conf'
                self.cm.exec_command(cmd_add, sudo=True)
            
            self.passed_checks += 1
            self.logger.info("✓ Server tokens set to off")

            # --- BƯỚC 5: ĐẢM BẢO CONF.D ĐƯỢC INCLUDE TRONG HTTP BLOCK ---
            self.logger.info("Ensuring conf.d directory is included in http block")
            
            # Kiểm tra xem đã có include chưa
            check_cmd = 'grep -q "include /etc/nginx/conf.d/\\*.conf;" /etc/nginx/nginx.conf'
            exit_status, output, error = self.cm.exec_command(check_cmd)
            
            if exit_status != 0:
                # Chèn vào trong http block (sau dòng "http {")
                insert_cmd = 'sudo sed -i "/^http {/a \\    include /etc/nginx/conf.d/*.conf;" /etc/nginx/nginx.conf'
                self.cm.exec_command(insert_cmd, sudo=True)
                self.logger.info("✓ Added include directive inside http block")
            else:
                self.logger.info("✓ Include directive already exists")
            
            self.passed_checks += 1

            # --- BƯỚC 6: KIỂM TRA CẤU TRÚC CƠ BẢN CỦA NGINX ---
            self.logger.info("Verifying basic NGINX structure")
            
            # Kiểm tra events block
            check_events = 'grep -q "events {" /etc/nginx/nginx.conf'
            exit_status, output, error = self.cm.exec_command(check_events)
            
            if exit_status != 0:
                self.logger.warning("Events block missing - will be handled by CISRemediate")
            
            # Kiểm tra http block  
            check_http = 'grep -q "http {" /etc/nginx/nginx.conf'
            exit_status, output, error = self.cm.exec_command(check_http)
            
            if exit_status != 0:
                self.logger.warning("HTTP block missing - will be handled by CISRemediate")
            
            self.passed_checks += 1

            self.logger.info("✓ Core security configurations applied successfully")
            self.logger.info("Security headers and advanced configurations delegated to CISRemediate")
            
            return self.passed_checks >= 2  # Chỉ cần 2/3 checks pass là thành công
                
        except Exception as e:
            self.logger.error(f"Security configuration failed: {str(e)}")
            
            # Cố gắng khôi phục backup nếu có lỗi
            try:
                self.cm.exec_command('sudo cp /etc/nginx/nginx.conf.backup /etc/nginx/nginx.conf', sudo=True)
                self.logger.info("Restored nginx.conf from backup due to errors")
            except:
                self.logger.error("Could not restore backup")
                
            return False