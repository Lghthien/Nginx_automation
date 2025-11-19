import paramiko
from getpass import getpass
import logging
import time

class ConnectionManager:
    def __init__(self, host, username=None, password=None, key_file=None):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.ssh = None
        self.logger = logging.getLogger(__name__)
        
    def connect(self):
        """Thiết lập kết nối SSH đến host"""
        try:
            if not self.username:
                self.username = input(f"Enter username for {self.host}: ")
            
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Kết nối với key file hoặc password
            if self.key_file:
                self.logger.info(f"Connecting to {self.host} with key file: {self.key_file}")
                self.ssh.connect(
                    self.host, 
                    username=self.username, 
                    key_filename=self.key_file,
                    look_for_keys=False,
                    timeout=30
                )
            else:
                if not self.password:
                    self.password = getpass(f"Enter password for {self.username}@{self.host}: ")
                
                self.logger.info(f"Connecting to {self.host}:22")
                self.ssh.connect(
                    self.host, 
                    username=self.username, 
                    password=self.password,
                    look_for_keys=False,
                    timeout=30
                )
            
            # Test kết nối và sudo access
            test_commands = [
                'echo "SSH Connection Test"',
                'sudo -n echo "Sudo Access Test"'
            ]
            
            for cmd in test_commands:
                stdin, stdout, stderr = self.ssh.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    self.logger.warning(f"Test command failed: {cmd}")
            
            self.logger.info(f"Connected to {self.host}:22")
            return True
                
        except paramiko.AuthenticationException:
            self.logger.error(f"Authentication failed for {self.username}@{self.host}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to connect to {self.host}: {str(e)}")
            return False
    
    def exec_command(self, command, sudo=False):
        """Thực thi command trên host với khả năng sudo"""
        try:
            if sudo:
                # Sử dụng sudo với timeout và xử lý password
                full_command = f'sudo -S -p "" {command}'
                stdin, stdout, stderr = self.ssh.exec_command(full_command, timeout=60)
                
                # Gửi password nếu cần và không có sẵn sudo session
                if self.password:
                    stdin.write(f"{self.password}\n")
                    stdin.flush()
            else:
                full_command = command
                stdin, stdout, stderr = self.ssh.exec_command(full_command, timeout=30)
                
            # Chờ command hoàn thành
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            # Xử lý sudo password prompt trong error output
            if '[sudo] password' in error:
                error = error.split('\n', 1)[-1]  # Bỏ dòng password prompt
            
            return exit_status, output, error
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {command}, Error: {str(e)}")
            return -1, "", str(e)
    
    def close(self):
        """Đóng kết nối SSH"""
        if self.ssh:
            self.ssh.close()
            self.logger.info(f"SSH connection closed for {self.host}")