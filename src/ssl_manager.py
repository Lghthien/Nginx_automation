"""SSL/TLS Certificate Manager for NGINX."""

import os
import logging
from datetime import datetime, timedelta
from typing import Tuple
from pathlib import Path
import tempfile

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.backends import default_backend

from src.ssh_manager import SSHManager


class SSLManager:
    """Manage SSL/TLS certificates and keys for NGINX."""
    
    def __init__(self, ssh_manager: SSHManager):
        """
        Initialize SSL Manager.
        
        Args:
            ssh_manager: SSHManager instance for remote operations
        """
        self.ssh = ssh_manager
        self.logger = logging.getLogger("nginx_cis.ssl")
    
    def generate_self_signed_cert(
        self,
        common_name: str = "localhost",
        organization: str = "NGINX CIS Benchmark",
        country: str = "US",
        validity_days: int = 365
    ) -> Tuple[str, str]:
        """
        Generate a self-signed SSL certificate and private key.
        
        Args:
            common_name: Common Name (CN) for certificate
            organization: Organization name
            country: Country code (2 letters)
            validity_days: Certificate validity in days
            
        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        try:
            self.logger.info(f"Generating self-signed certificate for {common_name}")
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Create certificate subject
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name)
            ])
            
            # Build certificate
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(common_name),
                    x509.DNSName("localhost"),
                    x509.DNSName("*.localhost"),
                ]),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Serialize certificate to PEM
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            # Serialize private key to PEM
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            self.logger.info("Successfully generated self-signed certificate")
            
            return cert_pem, key_pem
            
        except Exception as e:
            self.logger.error(f"Failed to generate self-signed certificate: {e}")
            raise
    
    def generate_dhparam(self, key_size: int = 2048) -> str:
        """
        Generate Diffie-Hellman parameters.
        
        Args:
            key_size: Size of DH parameters (2048 or 4096)
            
        Returns:
            DH parameters in PEM format
        """
        try:
            self.logger.info(f"Generating {key_size}-bit Diffie-Hellman parameters (this may take a while)...")
            
            # Generate DH parameters
            parameters = dh.generate_parameters(
                generator=2,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Serialize to PEM
            pem = parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            ).decode('utf-8')
            
            self.logger.info("Successfully generated Diffie-Hellman parameters")
            
            return pem
            
        except Exception as e:
            self.logger.error(f"Failed to generate DH parameters: {e}")
            raise
    
    def upload_certificates(
        self,
        cert_pem: str,
        key_pem: str,
        dhparam_pem: str,
        cert_path: str = "/etc/nginx/ssl/nginx.crt",
        key_path: str = "/etc/nginx/ssl/nginx.key",
        dhparam_path: str = "/etc/nginx/ssl/dhparam.pem"
    ) -> None:
        """
        Upload SSL certificates and keys to remote host with proper permissions.
        
        Args:
            cert_pem: Certificate in PEM format
            key_pem: Private key in PEM format
            dhparam_pem: DH parameters in PEM format
            cert_path: Remote path for certificate
            key_path: Remote path for private key
            dhparam_path: Remote path for DH parameters
        """
        try:
            self.logger.info("Uploading SSL certificates to remote host")
            
            # Create SSL directory
            ssl_dir = str(Path(cert_path).parent)
            self.ssh.execute_command(f"mkdir -p {ssl_dir}", sudo=True)
            
            # Upload certificate
            self.ssh.upload_content(cert_pem, cert_path, sudo=True)
            
            # Upload private key
            self.ssh.upload_content(key_pem, key_path, sudo=True)
            
            # Upload DH parameters
            self.ssh.upload_content(dhparam_pem, dhparam_path, sudo=True)
            
            # 4.1.3 Ensure private key permissions are restricted
            self.logger.info("Setting proper permissions on SSL files")
            self.ssh.execute_command(f"chmod 644 {cert_path}", sudo=True)
            self.ssh.execute_command(f"chmod 400 {key_path}", sudo=True)
            self.ssh.execute_command(f"chmod 644 {dhparam_path}", sudo=True)
            self.ssh.execute_command(f"chown root:root {cert_path} {key_path} {dhparam_path}", sudo=True)
            
            self.logger.info("Successfully uploaded SSL certificates with proper permissions")
            
        except Exception as e:
            self.logger.error(f"Failed to upload certificates: {e}")
            raise
    
    def generate_and_upload(
        self,
        common_name: str = None,
        cert_path: str = "/etc/nginx/ssl/nginx.crt",
        key_path: str = "/etc/nginx/ssl/nginx.key",
        dhparam_path: str = "/etc/nginx/ssl/dhparam.pem"
    ) -> None:
        """
        Generate and upload self-signed certificates and DH parameters.
        
        Args:
            common_name: Common name for certificate (defaults to hostname)
            cert_path: Remote path for certificate
            key_path: Remote path for private key
            dhparam_path: Remote path for DH parameters
        """
        try:
            # Use hostname as common name if not provided
            if not common_name:
                common_name = self.ssh.host_config.hostname
            
            # Generate certificate and key
            cert_pem, key_pem = self.generate_self_signed_cert(common_name=common_name)
            
            # Generate DH parameters
            dhparam_pem = self.generate_dhparam()
            
            # Upload all to remote host
            self.upload_certificates(
                cert_pem, key_pem, dhparam_pem,
                cert_path, key_path, dhparam_path
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate and upload certificates: {e}")
            raise
    
    def check_certificate_exists(
        self,
        cert_path: str = "/etc/nginx/ssl/nginx.crt",
        key_path: str = "/etc/nginx/ssl/nginx.key"
    ) -> bool:
        """
        Check if SSL certificates exist on remote host.
        
        Args:
            cert_path: Remote path to certificate
            key_path: Remote path to private key
            
        Returns:
            True if both certificate and key exist
        """
        try:
            return self.ssh.file_exists(cert_path) and self.ssh.file_exists(key_path)
        except Exception:
            return False

