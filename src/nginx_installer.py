"""NGINX Installer for CIS Benchmark compliance."""

import logging
from typing import Tuple

from src.ssh_manager import SSHManager


class NGINXInstaller:
    """Install and configure NGINX from official repository."""
    
    def __init__(self, ssh_manager: SSHManager):
        """
        Initialize NGINX Installer.
        
        Args:
            ssh_manager: SSHManager instance for remote operations
        """
        self.ssh = ssh_manager
        self.logger = logging.getLogger("nginx_cis.installer")
    
    def check_installed(self) -> bool:
        """
        Check if NGINX is already installed.
        
        Returns:
            True if NGINX is installed
        """
        try:
            stdout, _, exit_code = self.ssh.execute_command("which nginx")
            return exit_code == 0 and stdout.strip() != ""
        except Exception:
            return False
    
    def get_installed_version(self) -> str:
        """
        Get installed NGINX version.
        
        Returns:
            Version string or empty string if not installed
        """
        try:
            stdout, _, exit_code = self.ssh.execute_command("nginx -v 2>&1")
            if exit_code == 0:
                # Output format: nginx version: nginx/1.24.0
                version = stdout.strip().split('/')[-1] if '/' in stdout else ""
                return version
            return ""
        except Exception:
            return ""
    
    def install(self, from_official_repo: bool = True) -> None:
        """
        Install NGINX following CIS Benchmark 1.1.1.
        
        Args:
            from_official_repo: Install from official NGINX repository
        """
        try:
            # Check if already installed
            if self.check_installed():
                version = self.get_installed_version()
                self.logger.info(f"NGINX is already installed (version: {version})")
                return
            
            self.logger.info("Installing NGINX from official repository")
            
            if from_official_repo:
                self._install_from_official_repo()
            else:
                self._install_from_ubuntu_repo()
            
            # Verify installation
            if self.check_installed():
                version = self.get_installed_version()
                self.logger.info(f"NGINX successfully installed (version: {version})")
            else:
                raise Exception("NGINX installation verification failed")
            
        except Exception as e:
            self.logger.error(f"Failed to install NGINX: {e}")
            raise
    
    def _install_from_official_repo(self) -> None:
        """
        Install NGINX from official NGINX repository.
        Following CIS Benchmark 1.1.1 recommendations.
        """
        # Install prerequisites
        self.logger.debug("Installing prerequisites")
        stdout, stderr, exit_code = self.ssh.execute_command(
            "apt-get update && apt-get install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring",
            sudo=True,
            timeout=300
        )
        if exit_code != 0:
            raise Exception(f"Failed to install prerequisites: {stderr}")
        
        # Download and add NGINX signing key using tee (proper way to handle pipes with sudo)
        self.logger.debug("Downloading and installing NGINX signing key")
        stdout, stderr, exit_code = self.ssh.execute_command(
            "curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null",
            sudo=True,
            timeout=60
        )
        if exit_code != 0:
            raise Exception(f"Failed to install NGINX signing key: {stderr}")
        
        # Verify the key fingerprint (optional but recommended)
        self.logger.debug("Verifying NGINX signing key")
        stdout, stderr, exit_code = self.ssh.execute_command(
            "gpg --dry-run --quiet --no-keyring --import --import-options import-show /usr/share/keyrings/nginx-archive-keyring.gpg",
            sudo=True,
            timeout=30
        )
        if exit_code == 0 and "573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62" in stdout:
            self.logger.debug("NGINX signing key verified successfully")
        else:
            self.logger.warning("Could not verify NGINX signing key fingerprint")
        
        # Add NGINX repository using tee
        self.logger.debug("Adding NGINX repository")
        stdout, stderr, exit_code = self.ssh.execute_command(
            'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list >/dev/null',
            sudo=True,
            timeout=30
        )
        if exit_code != 0:
            raise Exception(f"Failed to add NGINX repository: {stderr}")
        
        # Set up repository pinning using tee
        self.logger.debug("Setting up repository pinning")
        stdout, stderr, exit_code = self.ssh.execute_command(
            'echo -e "Package: *\\nPin: origin nginx.org\\nPin: release o=nginx\\nPin-Priority: 900\\n" | tee /etc/apt/preferences.d/99nginx >/dev/null',
            sudo=True,
            timeout=30
        )
        if exit_code != 0:
            raise Exception(f"Failed to set up repository pinning: {stderr}")
        
        # Update package list
        self.logger.debug("Updating package list")
        stdout, stderr, exit_code = self.ssh.execute_command(
            "apt-get update",
            sudo=True,
            timeout=120
        )
        if exit_code != 0:
            raise Exception(f"Failed to update package list: {stderr}")
        
        # Install NGINX
        self.logger.debug("Installing NGINX package")
        stdout, stderr, exit_code = self.ssh.execute_command(
            "apt-get install -y nginx",
            sudo=True,
            timeout=300
        )
        if exit_code != 0:
            raise Exception(f"Failed to install NGINX: {stderr}")
    
    def _install_from_ubuntu_repo(self) -> None:
        """Install NGINX from Ubuntu repository (simpler but may not be latest)."""
        commands = [
            "apt-get update",
            "apt-get install -y nginx"
        ]
        
        for cmd in commands:
            self.logger.debug(f"Executing: {cmd}")
            stdout, stderr, exit_code = self.ssh.execute_command(cmd, sudo=True, timeout=300)
            
            if exit_code != 0:
                raise Exception(f"Installation command failed: {cmd}")
    
    def start_service(self) -> None:
        """Start NGINX service and enable it on boot."""
        try:
            self.logger.info("Starting NGINX service")
            
            # Start NGINX
            stdout, stderr, exit_code = self.ssh.execute_command(
                "systemctl start nginx",
                sudo=True
            )
            
            if exit_code != 0:
                raise Exception(f"Failed to start NGINX: {stderr}")
            
            # Enable NGINX to start on boot
            stdout, stderr, exit_code = self.ssh.execute_command(
                "systemctl enable nginx",
                sudo=True
            )
            
            if exit_code != 0:
                raise Exception(f"Failed to enable NGINX: {stderr}")
            
            self.logger.info("NGINX service started and enabled")
            
        except Exception as e:
            self.logger.error(f"Failed to start NGINX service: {e}")
            raise
    
    def stop_service(self) -> None:
        """Stop NGINX service."""
        try:
            self.logger.info("Stopping NGINX service")
            stdout, stderr, exit_code = self.ssh.execute_command(
                "systemctl stop nginx",
                sudo=True
            )
            
            if exit_code != 0:
                raise Exception(f"Failed to stop NGINX: {stderr}")
            
            self.logger.info("NGINX service stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop NGINX service: {e}")
            raise
    
    def restart_service(self) -> None:
        """Restart NGINX service."""
        try:
            self.logger.info("Restarting NGINX service")
            stdout, stderr, exit_code = self.ssh.execute_command(
                "systemctl restart nginx",
                sudo=True
            )
            
            if exit_code != 0:
                raise Exception(f"Failed to restart NGINX: {stderr}")
            
            self.logger.info("NGINX service restarted")
            
        except Exception as e:
            self.logger.error(f"Failed to restart NGINX service: {e}")
            raise
    
    def reload_service(self) -> None:
        """Reload NGINX configuration without stopping."""
        try:
            self.logger.info("Reloading NGINX configuration")
            stdout, stderr, exit_code = self.ssh.execute_command(
                "systemctl reload nginx",
                sudo=True
            )
            
            if exit_code != 0:
                # Try nginx -s reload instead
                stdout, stderr, exit_code = self.ssh.execute_command(
                    "nginx -s reload",
                    sudo=True
                )
                
                if exit_code != 0:
                    raise Exception(f"Failed to reload NGINX: {stderr}")
            
            self.logger.info("NGINX configuration reloaded")
            
        except Exception as e:
            self.logger.error(f"Failed to reload NGINX: {e}")
            raise
    
    def get_service_status(self) -> Tuple[bool, str]:
        """
        Get NGINX service status.
        
        Returns:
            Tuple of (is_running, status_text)
        """
        try:
            stdout, stderr, exit_code = self.ssh.execute_command(
                "systemctl is-active nginx",
                sudo=True
            )
            
            is_active = exit_code == 0 and "active" in stdout.strip()
            
            stdout, stderr, _ = self.ssh.execute_command(
                "systemctl status nginx",
                sudo=True
            )
            
            return is_active, stdout
            
        except Exception as e:
            self.logger.error(f"Failed to get service status: {e}")
            return False, str(e)
    
    def validate_config(self) -> Tuple[bool, str]:
        """
        Validate NGINX configuration.
        
        Returns:
            Tuple of (is_valid, output_message)
        """
        try:
            self.logger.info("Validating NGINX configuration")
            stdout, stderr, exit_code = self.ssh.execute_command(
                "nginx -t",
                sudo=True
            )
            
            output = stdout + stderr
            is_valid = exit_code == 0 and "syntax is ok" in output and "test is successful" in output
            
            if is_valid:
                self.logger.info("NGINX configuration is valid")
            else:
                self.logger.error(f"NGINX configuration validation failed: {output}")
            
            return is_valid, output
            
        except Exception as e:
            self.logger.error(f"Failed to validate configuration: {e}")
            return False, str(e)
    
    def verify_installation(self) -> bool:
        """
        Verify NGINX installation and basic functionality.
        
        Returns:
            True if installation is valid
        """
        try:
            # Check if nginx binary exists
            if not self.check_installed():
                self.logger.error("NGINX binary not found")
                return False
            
            # Get version
            version = self.get_installed_version()
            if not version:
                self.logger.error("Cannot determine NGINX version")
                return False
            
            self.logger.info(f"NGINX version: {version}")
            
            # Validate configuration
            is_valid, _ = self.validate_config()
            if not is_valid:
                self.logger.error("NGINX configuration is invalid")
                return False
            
            # Check service status
            is_running, status = self.get_service_status()
            if not is_running:
                self.logger.warning("NGINX service is not running")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Installation verification failed: {e}")
            return False

