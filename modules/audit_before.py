import logging

class AuditBefore:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 4
        self.passed_checks = 0

    def execute(self):
        try:
            self.logger.info("Performing pre-configuration audit")
            
            # Get NGINX version (nếu có)
            exit_status, output, error = self.cm.exec_command('nginx -v 2>&1')
            if exit_status == 0:
                self.logger.info(f"Current NGINX version: {output}")
                self.passed_checks += 1
            else:
                self.logger.info("NGINX not installed yet")

            # Check disk space
            exit_status, output, error = self.cm.exec_command("df -h / | awk 'NR==2{print $5}'")
            if exit_status == 0:
                self.logger.info(f"Disk space: {output}")
                self.passed_checks += 1

            # Check memory - sử dụng lệnh đơn giản hơn
            exit_status, output, error = self.cm.exec_command('free -h')
            if exit_status == 0:
                # Hiển thị thông tin memory đơn giản
                lines = output.split('\n')
                if len(lines) > 1:
                    mem_info = lines[1].split()
                    if len(mem_info) >= 7:
                        self.logger.info(f"Memory - Total: {mem_info[1]}, Used: {mem_info[2]}, Free: {mem_info[3]}")
                self.passed_checks += 1

            # Check system information
            exit_status, output, error = self.cm.exec_command('uname -a')
            if exit_status == 0:
                self.logger.info(f"System info: {output.split()[0]} {output.split()[2]}")
                self.passed_checks += 1

            self.logger.info("Pre-configuration audit completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Pre-configuration audit failed: {str(e)}")
            return False