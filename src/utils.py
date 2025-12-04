"""Utility functions for NGINX CIS Benchmark automation."""

import os
import yaml
import logging
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

from src.models import HostConfig


def load_yaml_config(config_path: str) -> List[HostConfig]:
    """
    Load hosts configuration from YAML file.
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        List of HostConfig objects
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format: {e}")
    
    if not config_data or 'hosts' not in config_data:
        raise ValueError("Configuration must contain 'hosts' key")
    
    hosts = []
    for idx, host_data in enumerate(config_data['hosts']):
        try:
            host = _parse_host_config(host_data)
            hosts.append(host)
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid host configuration at index {idx}: {e}")
    
    if not hosts:
        raise ValueError("No valid hosts found in configuration")
    
    return hosts


def _parse_host_config(host_data: Dict[str, Any]) -> HostConfig:
    """
    Parse a single host configuration from dictionary.
    
    Args:
        host_data: Dictionary containing host configuration
        
    Returns:
        HostConfig object
    """
    required_fields = ['hostname', 'ip', 'username']
    for field in required_fields:
        if field not in host_data:
            raise KeyError(f"Missing required field: {field}")
    
    # Expand private_key path if provided
    private_key = host_data.get('private_key')
    if private_key:
        private_key = os.path.expanduser(private_key)
        if not os.path.exists(private_key):
            raise ValueError(f"Private key file not found: {private_key}")
    
    return HostConfig(
        hostname=host_data['hostname'],
        ip=host_data['ip'],
        username=host_data['username'],
        port=host_data.get('port', 22),
        password=host_data.get('password'),
        private_key=private_key
    )


def validate_host_config(host: HostConfig) -> bool:
    """
    Validate a host configuration.
    
    Args:
        host: HostConfig object to validate
        
    Returns:
        True if valid
        
    Raises:
        ValueError: If configuration is invalid
    """
    if not host.hostname:
        raise ValueError("Hostname cannot be empty")
    
    if not host.ip:
        raise ValueError("IP address cannot be empty")
    
    if not host.username:
        raise ValueError("Username cannot be empty")
    
    if host.port < 1 or host.port > 65535:
        raise ValueError(f"Invalid port number: {host.port}")
    
    if not host.password and not host.private_key:
        raise ValueError("Either password or private_key must be provided")
    
    if host.private_key and not os.path.exists(host.private_key):
        raise ValueError(f"Private key file not found: {host.private_key}")
    
    return True


def setup_logging(log_dir: str = "logs", verbose: bool = False) -> logging.Logger:
    """
    Configure logging for the application.
    
    Args:
        log_dir: Directory to store log files
        verbose: Enable verbose (DEBUG) logging
        
    Returns:
        Configured logger instance
    """
    # Create log directory if it doesn't exist
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"nginx_cis_{timestamp}.log")
    
    # Configure logging level
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create logger
    logger = logging.getLogger("nginx_cis")
    logger.setLevel(log_level)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # File handler - detailed logging
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler - summary logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    logger.info(f"Logging initialized. Log file: {log_file}")
    
    return logger


def ensure_directory(directory: str) -> None:
    """
    Ensure a directory exists, create if it doesn't.
    
    Args:
        directory: Path to directory
    """
    Path(directory).mkdir(parents=True, exist_ok=True)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"

