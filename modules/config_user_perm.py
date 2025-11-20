import logging

class ConfigUserPerm:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 3
        self.passed_checks = 0

    def execute(self):
        try:
            self.logger.info("Configuring user and permissions (CIS 2.2.1, 2.3.1)")
            
            # --- 2.2.1 Ensure NGINX is run using a non-privileged, dedicated service account ---
            self.logger.info("Ensuring dedicated, non-privileged user 'nginx' exists.")
            user_exists = False
            exit_status, output, error = self.cm.exec_command('id nginx')
            if exit_status != 0:
                create_cmd = 'useradd -r -s /sbin/nologin nginx 2>/dev/null || useradd -r -s /bin/false nginx'
                exit_status, output, error = self.cm.exec_command(create_cmd, sudo=True)
                if exit_status == 0:
                    self.logger.info("Created nginx system user with nologin shell")
                    self.passed_checks += 1
                    user_exists = True
                else:
                    self.logger.warning(f"Failed to create nginx user: {error}. Assuming existing user.")
            else:
                self.logger.info("Nginx user already exists")
                self.passed_checks += 1
                user_exists = True

            if user_exists:
                self.logger.info("Configuring nginx.conf 'user nginx;'")
                cmd = "grep -q '^user nginx;' /etc/nginx/nginx.conf || sed -i '1i user nginx;' /etc/nginx/nginx.conf"
                self.cm.exec_command(cmd, sudo=True)
                self.passed_checks += 1
            
            # --- 2.3.1 Ensure NGINX directories and files are owned by root ---
            self.logger.info("Ensuring /etc/nginx is owned by root (CIS 2.3.1)")
            exit_status, output, error = self.cm.exec_command('chown -R root:root /etc/nginx', sudo=True)
            if exit_status == 0:
                self.logger.info("Set ownership of /etc/nginx to root:root")
                self.passed_checks += 1
            else:
                self.logger.warning(f"Failed to set ownership for /etc/nginx: {error}")

            self.logger.info("User and permissions configuration completed")
            return self.passed_checks >= 1
            
        except Exception as e:
            self.logger.error(f"User and permissions configuration failed: {str(e)}")
            return False