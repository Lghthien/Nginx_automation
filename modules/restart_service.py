import logging
import time

class RestartService:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 1
        self.passed_checks = 0
    
    def execute(self):
        try:
            self.logger.info("Restarting NGINX service")
            
            exit_status, output, error = self.cm.exec_command('which nginx')
            if exit_status != 0:
                self.logger.warning("NGINX not installed, skipping service restart")
                self.passed_checks = 1  
                return True

            self.logger.info("Attempting to reload NGINX...")
            exit_status, output, error = self.cm.exec_command('systemctl reload nginx', sudo=True)
            
            if exit_status == 0:
                self.logger.info("NGINX reloaded successfully")
                time.sleep(2)
                return self._check_nginx_status()
            else:
                self.logger.warning("Reload failed, trying restart...")
                exit_status, output, error = self.cm.exec_command('systemctl restart nginx', sudo=True)
                
                if exit_status == 0:
                    self.logger.info("NGINX restarted successfully")
                    time.sleep(2)
                    return self._check_nginx_status()
                else:
                    self.logger.error(f"Failed to restart NGINX: {error}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Service restart failed: {str(e)}")
            return False
    
    def _check_nginx_status(self):
        exit_status, output, error = self.cm.exec_command('systemctl is-active nginx', sudo=True)
        
        if exit_status == 0 and 'active' in output.lower():
            self.logger.info("NGINX is running and active")
            self.passed_checks = 1
            return True
        else:
            self.logger.warning(f"NGINX is not active: {output}")
            return False