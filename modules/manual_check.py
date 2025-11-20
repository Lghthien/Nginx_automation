import logging
import json
from typing import Tuple, List, Dict

class ManualCheck:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 1  # Chỉ tính là 1 bước thu thập
        self.passed_checks = 1
        self.manual_results = {}

    def run_command(self, cmd: str, sudo: bool = True) -> Tuple[int, str, str]:
        try:
            exit_status, stdout, stderr = self.cm.exec_command(cmd, sudo=sudo)
            return exit_status, stdout, stderr
        except:
            return 1, "", "Error during command execution"

    def _collect_manual_data(self, check_id: str, command: str, description: str):
        self.logger.info(f"Collecting data for {check_id}")
        exit_status, output, error = self.run_command(command, sudo=True)
        self.manual_results[check_id] = {
            "description": description,
            "command": command,
            "output_preview": output.strip()[:500] or error.strip()[:500],
            "status": "REQUIRES_MANUAL_REVIEW"
        }

    def execute(self):
        self.logger.info("Collecting data for Manual CIS Checks (e.g., Certificates, Ciphers)")

        # Thu thập dữ liệu cho các mục thủ công quan trọng (CIS 4.1.1, 4.1.5)
        self._collect_manual_data("4.1.1", 
            "grep -ir 'return 301 https' /etc/nginx", 
            "HTTP to HTTPS Redirection Status")
        
        self._collect_manual_data("4.1.5", 
            "grep -ir ssl_ciphers /etc/nginx/", 
            "Weak Ciphers/SSL_Ciphers Configuration")

        # Ghi kết quả ra file JSON
        with open("cis_manual_results.json", 'w') as f:
            json.dump(self.manual_results, f, indent=2)

        self.logger.info(f"Manual checks data saved to cis_manual_results.json")
        return True