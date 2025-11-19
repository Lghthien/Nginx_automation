import logging

class PrepareSystem:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 1
        self.passed_checks = 0

    def execute(self):
        try:
            self.logger.info("Preparing system for NGINX installation")
            
            # Update package lists
            exit_status, output, error = self.cm.exec_command('apt-get update', sudo=True)
            
            if exit_status == 0:
                self.logger.info("System updated successfully")
                self.passed_checks = 1
                return True
            else:
                self.logger.error(f"Failed to update package lists: {error}")
                return False
                
        except Exception as e:
            self.logger.error(f"System preparation failed: {str(e)}")
            return False