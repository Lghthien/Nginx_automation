import logging

class ConfigUserPerm:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 2
        self.passed_checks = 0

    def execute(self):
        try:
            self.logger.info("Configuring user and permissions")
            
            # Check if nginx user exists
            exit_status, output, error = self.cm.exec_command('id nginx')
            if exit_status != 0:
                # Create nginx user
                exit_status, output, error = self.cm.exec_command('useradd -r -s /bin/false nginx', sudo=True)
                if exit_status == 0:
                    self.logger.info("Created nginx user")
                    self.passed_checks += 1
                else:
                    self.logger.warning(f"Failed to create nginx user: {error}")
            else:
                self.logger.info("Nginx user already exists")
                self.passed_checks += 1

            # Set permissions for NGINX directories
            exit_status, output, error = self.cm.exec_command('chown -R nginx:nginx /var/log/nginx', sudo=True)
            if exit_status == 0:
                self.logger.info("Set permissions for NGINX logs")
                self.passed_checks += 1
            else:
                self.logger.warning(f"Failed to set permissions: {error}")

            self.logger.info("User and permissions configuration completed")
            return self.passed_checks >= 1
            
        except Exception as e:
            self.logger.error(f"User and permissions configuration failed: {str(e)}")
            return False