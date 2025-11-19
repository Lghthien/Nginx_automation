import logging

class AuditAfter:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 7
        self.passed_checks = 0

    def execute(self):
        try:
            self.logger.info("Performing post-configuration audit")
            
            # Kiểm tra xem NGINX đã được cài đặt chưa
            exit_status, output, error = self.cm.exec_command('which nginx')
            if exit_status != 0:
                self.logger.warning("NGINX not installed, performing limited audit")
                return self._perform_limited_audit()

            checks_passed = 0
            total_checks = 7

            # Check 1: NGINX status
            exit_status, output, error = self.cm.exec_command('systemctl is-active nginx', sudo=True)
            if exit_status == 0 and 'active' in output:
                self.logger.info("NGINX is active")
                checks_passed += 1
            else:
                self.logger.warning("NGINX is not active")
                # Kiểm tra lý do chi tiết
                exit_status, output, error = self.cm.exec_command('systemctl status nginx --no-pager', sudo=True)
                if exit_status != 0:
                    self.logger.error(f"NGINX status error: {error}")

            # Check 2: NGINX configuration
            exit_status, output, error = self.cm.exec_command('nginx -t', sudo=True)
            if exit_status == 0:
                self.logger.info("NGINX configuration is valid")
                checks_passed += 1
            else:
                self.logger.warning(f"NGINX configuration has issues: {error}")

            # Check 3: Server tokens (kiểm tra trong file config)
            exit_status, output, error = self.cm.exec_command('grep "server_tokens" /etc/nginx/nginx.conf', sudo=True)
            if exit_status == 0 and 'off' in output:
                self.logger.info("Server tokens are hidden")
                checks_passed += 1
            else:
                self.logger.warning("Server tokens are visible")

            # Check 4: NGINX listening on port 80
            self.logger.info("Checking if NGINX is listening on port 80...")
            exit_status, output, error = self.cm.exec_command('sudo ss -tulpn | grep ":80 " | grep nginx', sudo=True)
            if exit_status == 0:
                self.logger.info("NGINX is listening on port 80")
                checks_passed += 1
            else:
                self.logger.warning("NGINX is not listening on port 80")

            # Check 5: HTTP response
            exit_status, output, error = self.cm.exec_command('curl -s -o /dev/null -w "%{http_code}" http://localhost', sudo=True)
            if exit_status == 0 and output.strip() in ['200', '301', '302']:
                self.logger.info("HTTP test successful")
                checks_passed += 1
            else:
                self.logger.warning(f"HTTP test failed: Status {output}")

            # Check 6: Security config file
            exit_status, output, error = self.cm.exec_command('ls /etc/nginx/conf.d/security.conf', sudo=True)
            if exit_status == 0:
                self.logger.info("Security configuration file exists")
                checks_passed += 1
            else:
                self.logger.warning("Security configuration file not found")

            # Check 7: Port 80 conflict check
            exit_status, output, error = self.cm.exec_command('sudo ss -tulpn | grep ":80 " | grep -v nginx', sudo=True)
            if exit_status != 0:  # Không có process nào khác ngoài NGINX dùng port 80
                self.logger.info("No port 80 conflicts detected")
                checks_passed += 1
            else:
                self.logger.warning("Port 80 conflict detected with other processes")

            self.passed_checks = checks_passed
            compliance_rate = (checks_passed / total_checks) * 100
            
            self.logger.info(f"Post-audit compliance rate: {compliance_rate:.1f}% ({checks_passed}/{total_checks} checks passed)")

            if compliance_rate >= 80:
                self.logger.info("Good compliance level achieved")
            elif compliance_rate >= 60:
                self.logger.warning("Acceptable compliance level - some improvements needed")
            else:
                self.logger.warning("Low compliance level - review required")

            self.logger.info("Post-configuration audit completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Post-configuration audit failed: {str(e)}")
            return False

    def _perform_limited_audit(self):
        """Thực hiện audit giới hạn khi NGINX chưa được cài đặt"""
        self.logger.info("Performing limited audit (NGINX not installed)")
        
        checks_passed = 0
        total_checks = 3

        # Check 1: System prepared
        exit_status, output, error = self.cm.exec_command('which apt-get')
        if exit_status == 0:
            self.logger.info("System package manager available")
            checks_passed += 1

        # Check 2: Network connectivity
        exit_status, output, error = self.cm.exec_command('curl -s --connect-timeout 5 http://google.com > /dev/null && echo "OK"')
        if exit_status == 0 and 'OK' in output:
            self.logger.info("Network connectivity confirmed")
            checks_passed += 1
        else:
            self.logger.warning("Network connectivity issues")

        # Check 3: User permissions
        exit_status, output, error = self.cm.exec_command('id nginx')
        if exit_status == 0:
            self.logger.info("NGINX user exists")
            checks_passed += 1

        self.passed_checks = checks_passed
        compliance_rate = (checks_passed / total_checks) * 100
        
        self.logger.info(f"Limited audit compliance rate: {compliance_rate:.1f}%")
        self.logger.info("Consider installing NGINX manually and re-running the audit")
        
        return True