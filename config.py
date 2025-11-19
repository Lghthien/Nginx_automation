import os
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class SSHConfig:
    hosts: List[str] = None
    port: int = int(os.getenv('NGINX_SSH_PORT', '22'))
    username: str = os.getenv('NGINX_SSH_USERNAME', 'root')
    password: str = os.getenv('NGINX_SSH_PASSWORD', '')
    key_file: str = os.getenv('NGINX_SSH_KEY_FILE', '')
    timeout: int = int(os.getenv('NGINX_SSH_TIMEOUT', '30'))

@dataclass
class NGINXConfig:
    conf_path: str = '/etc/nginx/nginx.conf'
    conf_dir: str = '/etc/nginx/conf.d/'
    sites_available: str = '/etc/nginx/sites-available/'
    sites_enabled: str = '/etc/nginx/sites-enabled/'
    log_dir: str = '/var/log/nginx/'
    backup_dir: str = '/etc/nginx/backup/'

@dataclass
class AppConfig:
    log_level: str = os.getenv('NGINX_LOG_LEVEL', 'INFO')
    output_format: str = os.getenv('NGINX_OUTPUT_FORMAT', 'html')
    backup_config: bool = True
    cis_level: int = int(os.getenv('NGINX_CIS_LEVEL', '2'))
    nginx_version: str = '1.22.0'
    # THÊM DÒNG NÀY - Quan trọng!
    nginx_config: NGINXConfig = None
    
    def __post_init__(self):
        if self.nginx_config is None:
            self.nginx_config = NGINXConfig()

# Khởi tạo config
nginx_config = NGINXConfig()
app_config = AppConfig(nginx_config=nginx_config)
ssh_config = SSHConfig()

# CIS Benchmark configurations for Level 1 & 2
CIS_BENCHMARKS = {
    '1.1.1': {'description': 'Ensure NGINX is installed', 'level': 1, 'automated': True},
    '1.2.1': {'description': 'Ensure package manager repositories are configured', 'level': 1, 'automated': False},
    '1.2.2': {'description': 'Ensure latest software package is installed', 'level': 1, 'automated': False},
    '2.1.2': {'description': 'Ensure HTTP WebDAV module is not installed', 'level': 2, 'automated': True},
    '2.1.3': {'description': 'Ensure modules with gzip functionality are disabled', 'level': 2, 'automated': True},
    '2.1.4': {'description': 'Ensure the autoindex module is disabled', 'level': 1, 'automated': True},
    '2.2.1': {'description': 'Ensure NGINX runs with non-privileged dedicated account', 'level': 1, 'automated': True},
    '2.2.2': {'description': 'Ensure NGINX service account is locked', 'level': 1, 'automated': True},
    '2.2.3': {'description': 'Ensure NGINX service account has invalid shell', 'level': 1, 'automated': True},
    '2.3.1': {'description': 'Ensure NGINX directories and files are owned by root', 'level': 1, 'automated': True},
    '2.3.2': {'description': 'Ensure access to NGINX directories and files is restricted', 'level': 1, 'automated': True},
    '2.4.3': {'description': 'Ensure keepalive_timeout is 10 seconds or less', 'level': 1, 'automated': True},
    '2.4.4': {'description': 'Ensure send_timeout is 10 seconds or less', 'level': 1, 'automated': True},
    '2.5.1': {'description': 'Ensure server_tokens directive is set to off', 'level': 1, 'automated': True},
    '3.3': {'description': 'Ensure error logging is enabled and set to info level', 'level': 1, 'automated': True},
    '3.4': {'description': 'Ensure log files are rotated', 'level': 1, 'automated': True},
    '4.1.12': {'description': 'Ensure session resumption is disabled', 'level': 2, 'automated': True},
    '4.1.13': {'description': 'Ensure HTTP/2.0 is used', 'level': 2, 'automated': True},
}

