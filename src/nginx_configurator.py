"""NGINX Configurator for CIS Benchmark compliance."""

import logging
from datetime import datetime
from typing import Optional

from src.ssh_manager import SSHManager
from src.nginx_installer import NGINXInstaller
from src.ssl_manager import SSLManager
from src.config_templates import (
    generate_nginx_conf,
    generate_default_server_conf,
    generate_logrotate_conf
)


class NGINXConfigurator:
    """Configure NGINX according to CIS Benchmark recommendations."""
    
    def __init__(self, ssh_manager: SSHManager):
        """
        Initialize NGINX Configurator.
        
        Args:
            ssh_manager: SSHManager instance for remote operations
        """
        self.ssh = ssh_manager
        self.installer = NGINXInstaller(ssh_manager)
        self.ssl_manager = SSLManager(ssh_manager)
        self.logger = logging.getLogger("nginx_cis.configurator")
        
        self.nginx_user = "nginx"
        self.nginx_conf_path = "/etc/nginx/nginx.conf"
        self.nginx_conf_dir = "/etc/nginx"
        self.default_site_path = "/etc/nginx/conf.d/default.conf"
        self.ssl_dir = "/etc/nginx/ssl"
        self.log_dir = "/var/log/nginx"
        self.backup_dir = "/etc/nginx/backup"
    
    def configure(self, server_name: Optional[str] = None) -> None:
        """
        Complete NGINX configuration following CIS Benchmark.
        
        Args:
            server_name: Server name for HTTPS configuration
        """
        try:
            self.logger.info("Starting NGINX CIS Benchmark configuration")
            
            # Backup existing configuration
            self._backup_config()
            
            # Create nginx user if doesn't exist (2.2.1)
            self._create_nginx_user()
            
            # Create necessary directories
            self._create_directories()
            
            # Generate and upload SSL certificates
            self.logger.info("Generating SSL certificates")
            self.ssl_manager.generate_and_upload(
                common_name=server_name or self.ssh.host_config.hostname
            )
            
            # Generate and upload NGINX configurations
            self._upload_nginx_conf()
            self._upload_default_site(server_name)
            self._setup_logrotate()
            
            # Set proper ownership and permissions
            self._set_permissions()
            
            # Secure core dump directory (2.3.4)
            self._secure_core_dump_directory()
            
            # Create default website content
            self._create_default_website()
            
            # Remove default Ubuntu/Debian site if exists
            self._remove_default_sites()
            
            # Validate configuration
            is_valid, output = self.installer.validate_config()
            if not is_valid:
                self.logger.error("Configuration validation failed, attempting rollback")
                self.rollback()
                raise Exception(f"Configuration validation failed: {output}")
            
            # Reload NGINX
            self.installer.reload_service()
            
            self.logger.info("NGINX CIS Benchmark configuration completed successfully")
            
        except Exception as e:
            self.logger.error(f"Configuration failed: {e}")
            raise
    
    def _backup_config(self) -> None:
        """Backup existing NGINX configuration."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.backup_dir}/nginx_conf_{timestamp}"
            
            self.logger.info(f"Backing up NGINX configuration to {backup_path}")
            
            # Create backup directory
            self.ssh.execute_command(f"mkdir -p {backup_path}", sudo=True)
            
            # Backup configuration directory
            self.ssh.execute_command(
                f"cp -r {self.nginx_conf_dir}/* {backup_path}/ 2>/dev/null || true",
                sudo=True
            )
            
            self.logger.info("Configuration backup completed")
            
        except Exception as e:
            self.logger.warning(f"Failed to backup configuration: {e}")
    
    def _create_nginx_user(self) -> None:
        """
        Create NGINX user according to CIS 2.2.1, 2.2.2, 2.2.3.
        - Non-privileged user
        - Locked account
        - Invalid shell
        """
        try:
            self.logger.info(f"Creating/updating {self.nginx_user} user")
            
            # Check if user exists
            stdout, _, exit_code = self.ssh.execute_command(f"id {self.nginx_user}")
            
            if exit_code != 0:
                # Create user with no login shell and no home directory
                self.ssh.execute_command(
                    f"useradd --system --no-create-home --shell /usr/sbin/nologin {self.nginx_user}",
                    sudo=True
                )
                self.logger.info(f"Created {self.nginx_user} user")
            else:
                # Update existing user
                self.ssh.execute_command(
                    f"usermod --shell /usr/sbin/nologin {self.nginx_user}",
                    sudo=True
                )
                self.logger.info(f"Updated {self.nginx_user} user")
            
            # Lock the account (2.2.2)
            self.ssh.execute_command(f"passwd -l {self.nginx_user}", sudo=True)
            
        except Exception as e:
            self.logger.error(f"Failed to create/update nginx user: {e}")
            raise
    
    def _create_directories(self) -> None:
        """Create necessary directories for NGINX."""
        try:
            directories = [
                self.ssl_dir,
                self.log_dir,
                "/var/lib/nginx",  # Working directory for core dumps
                "/var/cache/nginx",
                "/etc/nginx/conf.d",
                "/etc/nginx/sites-available",
                "/etc/nginx/sites-enabled"
            ]
            
            for directory in directories:
                self.ssh.execute_command(f"mkdir -p {directory}", sudo=True)
            
        except Exception as e:
            self.logger.error(f"Failed to create directories: {e}")
            raise
    
    def _upload_nginx_conf(self) -> None:
        """Generate and upload main nginx.conf."""
        try:
            self.logger.info("Uploading nginx.conf")
            
            # Generate configuration
            nginx_conf = generate_nginx_conf(
                user=self.nginx_user,
                error_log=f"{self.log_dir}/error.log",
                access_log=f"{self.log_dir}/access.log"
            )
            
            # Upload configuration
            self.ssh.upload_content(nginx_conf, self.nginx_conf_path, sudo=True)
            
            self.logger.info("nginx.conf uploaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to upload nginx.conf: {e}")
            raise
    
    def _upload_default_site(self, server_name: Optional[str] = None) -> None:
        """Generate and upload default site configuration."""
        try:
            self.logger.info("Uploading default site configuration")
            
            if not server_name:
                server_name = self.ssh.host_config.ip
            
            # Generate configuration
            site_conf = generate_default_server_conf(
                server_name=server_name,
                ssl_cert_path=f"{self.ssl_dir}/nginx.crt",
                ssl_key_path=f"{self.ssl_dir}/nginx.key",
                dhparam_path=f"{self.ssl_dir}/dhparam.pem",
                access_log=f"{self.log_dir}/access.log",
                error_log=f"{self.log_dir}/error.log"
            )
            
            # Upload configuration
            self.ssh.upload_content(site_conf, self.default_site_path, sudo=True)
            
            self.logger.info("Default site configuration uploaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to upload default site configuration: {e}")
            raise
    
    def _setup_logrotate(self) -> None:
        """Setup logrotate for NGINX logs (CIS 3.4)."""
        try:
            self.logger.info("Setting up logrotate for NGINX")
            
            # Generate logrotate configuration
            logrotate_conf = generate_logrotate_conf(f"{self.log_dir}/*.log")
            
            # Upload configuration
            self.ssh.upload_content(
                logrotate_conf,
                "/etc/logrotate.d/nginx",
                sudo=True
            )
            
            self.logger.info("Logrotate configuration set up successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to setup logrotate: {e}")
    
    def _set_permissions(self) -> None:
        """
        Set proper ownership and permissions for NGINX files.
        Following CIS 2.3.1, 2.3.2, 2.3.3, 4.1.3
        """
        try:
            self.logger.info("Setting proper file permissions")
            
            # 2.3.1 Ensure NGINX directories and files are owned by root
            self.ssh.execute_command(
                f"chown -R root:root {self.nginx_conf_dir}",
                sudo=True
            )
            
            # 2.3.2 Ensure access to NGINX directories and files is restricted
            # Config files: 644
            self.ssh.execute_command(
                f"find {self.nginx_conf_dir} -type f -exec chmod 644 {{}} \\;",
                sudo=True
            )
            
            # Directories: 755
            self.ssh.execute_command(
                f"find {self.nginx_conf_dir} -type d -exec chmod 755 {{}} \\;",
                sudo=True
            )
            
            # 4.1.3 Private key permissions: 400
            self.ssh.execute_command(
                f"chmod 400 {self.ssl_dir}/*.key 2>/dev/null || true",
                sudo=True
            )
            
            # 2.3.3 PID file permissions
            self.ssh.execute_command(
                "chmod 644 /var/run/nginx.pid 2>/dev/null || true",
                sudo=True
            )
            
            # Log directory: nginx user should be able to write
            self.ssh.execute_command(
                f"chown -R {self.nginx_user}:adm {self.log_dir}",
                sudo=True
            )
            self.ssh.execute_command(
                f"chmod 750 {self.log_dir}",
                sudo=True
            )
            
            self.logger.info("File permissions set successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to set permissions: {e}")
            raise
    
    def _secure_core_dump_directory(self) -> None:
        """Secure core dump directory (CIS 2.3.4)."""
        try:
            self.logger.info("Securing core dump directory")
            
            working_dir = "/var/lib/nginx"
            
            # Create directory if doesn't exist
            self.ssh.execute_command(f"mkdir -p {working_dir}", sudo=True)
            
            # Set ownership and permissions
            # nginx user needs to chdir into this directory, so ownership must be nginx:root
            # CIS requires the directory to be secured - 750 allows nginx user full access
            # while restricting others
            self.ssh.execute_command(f"chown {self.nginx_user}:root {working_dir}", sudo=True)
            self.ssh.execute_command(f"chmod 750 {working_dir}", sudo=True)
            
            self.logger.info("Core dump directory secured")
            
        except Exception as e:
            self.logger.warning(f"Failed to secure core dump directory: {e}")
    
    def _create_default_website(self) -> None:
        """Create default website content."""
        try:
            self.logger.info("Creating default website content")
            
            # Create web root directory
            web_root = "/var/www/html"
            self.ssh.execute_command(f"mkdir -p {web_root}", sudo=True)
            
            # Create default index.html
            default_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NGINX Installed</title>
    <style>
        body {
            background: #f8fafc;
            font-family: Arial, sans-serif;
            color: #222;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .message {
            background: #fff;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.03);
            padding: 40px 50px;
            text-align: center;
        }
        .message h1 {
            font-size: 2em;
            margin-bottom: 12px;
            color: #2d3748;
        }
        .message p {
            font-size: 1em;
            color: #4a5568;
        }
    </style>
</head>
<body>
    <div class="message">
        <h1>NGINX has been installed successfully!</h1>
        <p>This is the default index page. You can safely replace it with your own content.</p>
    </div>
</body>
</html>"""
            
            # Upload HTML content
            self.ssh.upload_content(default_html, f"{web_root}/index.html", sudo=True)
            
            # Set proper ownership and permissions
            self.ssh.execute_command(f"chown -R {self.nginx_user}:{self.nginx_user} {web_root}", sudo=True)
            self.ssh.execute_command(f"chmod -R 755 {web_root}", sudo=True)
            self.ssh.execute_command(f"chmod 644 {web_root}/index.html", sudo=True)
            
            self.logger.info("Default website content created successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to create default website: {e}")
    
    def _remove_default_sites(self) -> None:
        """Remove default Ubuntu/Debian site configurations."""
        try:
            self.logger.info("Removing default site configurations")
            
            # Remove default sites
            default_files = [
                "/etc/nginx/sites-enabled/default",
                "/etc/nginx/conf.d/default.conf.bak"
            ]
            
            for file_path in default_files:
                self.ssh.execute_command(f"rm -f {file_path}", sudo=True)
            
        except Exception as e:
            self.logger.warning(f"Failed to remove default sites: {e}")
    
    def rollback(self) -> None:
        """Rollback to previous configuration."""
        try:
            self.logger.info("Rolling back NGINX configuration")
            
            # Find most recent backup
            stdout, _, exit_code = self.ssh.execute_command(
                f"ls -t {self.backup_dir} | head -1",
                sudo=True
            )
            
            if exit_code == 0 and stdout.strip():
                backup_name = stdout.strip()
                backup_path = f"{self.backup_dir}/{backup_name}"
                
                self.logger.info(f"Restoring from backup: {backup_path}")
                
                # Restore configuration
                self.ssh.execute_command(
                    f"cp -r {backup_path}/* {self.nginx_conf_dir}/",
                    sudo=True
                )
                
                # Reload NGINX
                self.installer.reload_service()
                
                self.logger.info("Configuration rolled back successfully")
            else:
                self.logger.warning("No backup found for rollback")
            
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            raise
    
    def get_config_status(self) -> dict:
        """
        Get current NGINX configuration status.
        
        Returns:
            Dictionary with configuration details
        """
        try:
            status = {
                "nginx_installed": self.installer.check_installed(),
                "nginx_version": self.installer.get_installed_version(),
                "service_running": False,
                "config_valid": False,
                "ssl_configured": False
            }
            
            # Check service status
            is_running, _ = self.installer.get_service_status()
            status["service_running"] = is_running
            
            # Check config validity
            is_valid, _ = self.installer.validate_config()
            status["config_valid"] = is_valid
            
            # Check SSL certificates
            status["ssl_configured"] = self.ssl_manager.check_certificate_exists()
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get config status: {e}")
            return {}

