"""SSH Manager for remote host operations."""

import paramiko
import logging
from typing import Tuple, Optional
import time
from pathlib import Path

from src.models import HostConfig


class SSHManager:
    """Manage SSH connections and operations on remote hosts."""
    
    def __init__(self, host_config: HostConfig):
        """
        Initialize SSH Manager.
        
        Args:
            host_config: Configuration for the target host
        """
        self.host_config = host_config
        self.client: Optional[paramiko.SSHClient] = None
        self.sftp: Optional[paramiko.SFTPClient] = None
        self.logger = logging.getLogger("nginx_cis.ssh")
    
    def connect(self, timeout: int = 30) -> None:
        """
        Establish SSH connection to the remote host.
        
        Args:
            timeout: Connection timeout in seconds
            
        Raises:
            Exception: If connection fails
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.host_config.ip,
                'port': self.host_config.port,
                'username': self.host_config.username,
                'timeout': timeout,
                'banner_timeout': timeout
            }
            
            # Use password or private key authentication
            if self.host_config.private_key:
                self.logger.debug(f"Connecting to {self.host_config.hostname} using private key")
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(self.host_config.private_key)
                    connect_kwargs['pkey'] = private_key
                except paramiko.ssh_exception.SSHException:
                    # Try as DSA key
                    try:
                        private_key = paramiko.DSSKey.from_private_key_file(self.host_config.private_key)
                        connect_kwargs['pkey'] = private_key
                    except paramiko.ssh_exception.SSHException:
                        # Try as ECDSA key
                        try:
                            private_key = paramiko.ECDSAKey.from_private_key_file(self.host_config.private_key)
                            connect_kwargs['pkey'] = private_key
                        except paramiko.ssh_exception.SSHException:
                            # Try as Ed25519 key
                            private_key = paramiko.Ed25519Key.from_private_key_file(self.host_config.private_key)
                            connect_kwargs['pkey'] = private_key
            else:
                self.logger.debug(f"Connecting to {self.host_config.hostname} using password")
                connect_kwargs['password'] = self.host_config.password
            
            self.client.connect(**connect_kwargs)
            self.logger.info(f"Successfully connected to {self.host_config.hostname} ({self.host_config.ip})")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to {self.host_config.hostname}: {e}")
            raise
    
    def execute_command(self, command: str, sudo: bool = False, timeout: int = 300) -> Tuple[str, str, int]:
        """
        Execute a command on the remote host.
        
        Args:
            command: Command to execute
            sudo: Execute with sudo privileges
            timeout: Command execution timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
            
        Raises:
            Exception: If command execution fails
        """
        if not self.client:
            raise Exception("Not connected to host. Call connect() first.")
        
        try:
            if sudo:
                # Escape single quotes in command for bash -c
                escaped_command = command.replace("'", "'\"'\"'")
                # Use bash -c to ensure entire command runs with sudo privileges
                command = f"sudo -S bash -c '{escaped_command}'"
            
            self.logger.debug(f"Executing command: {command}")
            
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            # If sudo, send password
            if sudo and self.host_config.password:
                stdin.write(self.host_config.password + '\n')
                stdin.flush()
            
            # Read output
            stdout_text = stdout.read().decode('utf-8', errors='ignore')
            stderr_text = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()
            
            self.logger.debug(f"Command exit code: {exit_code}")
            
            return stdout_text, stderr_text, exit_code
            
        except Exception as e:
            self.logger.error(f"Failed to execute command: {e}")
            raise
    
    def upload_file(self, local_path: str, remote_path: str) -> None:
        """
        Upload a file to the remote host using SFTP.
        
        Args:
            local_path: Path to local file
            remote_path: Destination path on remote host
            
        Raises:
            Exception: If upload fails
        """
        if not self.client:
            raise Exception("Not connected to host. Call connect() first.")
        
        try:
            if not self.sftp:
                self.sftp = self.client.open_sftp()
            
            self.logger.debug(f"Uploading {local_path} to {remote_path}")
            
            # Ensure remote directory exists
            remote_dir = str(Path(remote_path).parent)
            try:
                self.sftp.stat(remote_dir)
            except FileNotFoundError:
                # Create directory recursively
                self.execute_command(f"mkdir -p {remote_dir}", sudo=True)
            
            self.sftp.put(local_path, remote_path)
            self.logger.info(f"Uploaded {local_path} to {remote_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to upload file: {e}")
            raise
    
    def upload_content(self, content: str, remote_path: str, sudo: bool = False) -> None:
        """
        Upload content as a file to the remote host.
        
        Args:
            content: Content to upload
            remote_path: Destination path on remote host
            sudo: Whether to use sudo for file operations
            
        Raises:
            Exception: If upload fails
        """
        if not self.client:
            raise Exception("Not connected to host. Call connect() first.")
        
        try:
            # Write to temporary file first
            temp_path = f"/tmp/nginx_cis_{int(time.time())}.tmp"
            
            if not self.sftp:
                self.sftp = self.client.open_sftp()
            
            self.logger.debug(f"Uploading content to {remote_path}")
            
            # Write content to temp file
            with self.sftp.open(temp_path, 'w') as f:
                f.write(content)
            
            # Move to final location with sudo if needed
            if sudo:
                self.execute_command(f"mkdir -p {str(Path(remote_path).parent)}", sudo=True)
                self.execute_command(f"mv {temp_path} {remote_path}", sudo=True)
            else:
                self.execute_command(f"mkdir -p {str(Path(remote_path).parent)}")
                self.execute_command(f"mv {temp_path} {remote_path}")
            
            self.logger.info(f"Uploaded content to {remote_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to upload content: {e}")
            raise
    
    def download_file(self, remote_path: str, local_path: str) -> None:
        """
        Download a file from the remote host using SFTP.
        
        Args:
            remote_path: Path to file on remote host
            local_path: Destination path on local machine
            
        Raises:
            Exception: If download fails
        """
        if not self.client:
            raise Exception("Not connected to host. Call connect() first.")
        
        try:
            if not self.sftp:
                self.sftp = self.client.open_sftp()
            
            self.logger.debug(f"Downloading {remote_path} to {local_path}")
            
            # Ensure local directory exists
            Path(local_path).parent.mkdir(parents=True, exist_ok=True)
            
            self.sftp.get(remote_path, local_path)
            self.logger.info(f"Downloaded {remote_path} to {local_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to download file: {e}")
            raise
    
    def file_exists(self, remote_path: str) -> bool:
        """
        Check if a file exists on the remote host.
        
        Args:
            remote_path: Path to check
            
        Returns:
            True if file exists, False otherwise
        """
        try:
            stdout, _, exit_code = self.execute_command(f"test -e {remote_path} && echo exists")
            return exit_code == 0 and "exists" in stdout
        except Exception:
            return False
    
    def read_file(self, remote_path: str, sudo: bool = False) -> str:
        """
        Read content of a file on the remote host.
        
        Args:
            remote_path: Path to file on remote host
            sudo: Use sudo to read file
            
        Returns:
            File content as string
            
        Raises:
            Exception: If read fails
        """
        try:
            if sudo:
                stdout, stderr, exit_code = self.execute_command(f"cat {remote_path}", sudo=True)
            else:
                stdout, stderr, exit_code = self.execute_command(f"cat {remote_path}")
            
            if exit_code != 0:
                raise Exception(f"Failed to read file: {stderr}")
            
            return stdout
            
        except Exception as e:
            self.logger.error(f"Failed to read file {remote_path}: {e}")
            raise
    
    def close(self) -> None:
        """Close the SSH connection."""
        try:
            if self.sftp:
                self.sftp.close()
                self.sftp = None
            
            if self.client:
                self.client.close()
                self.client = None
            
            self.logger.info(f"Closed connection to {self.host_config.hostname}")
            
        except Exception as e:
            self.logger.error(f"Error closing connection: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

