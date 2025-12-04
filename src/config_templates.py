"""NGINX configuration templates following CIS Benchmark recommendations."""

from typing import Dict, Any


def generate_nginx_conf(
    worker_processes: str = "auto",
    worker_connections: int = 1024,
    user: str = "nginx",
    error_log: str = "/var/log/nginx/error.log",
    access_log: str = "/var/log/nginx/access.log",
    pid_file: str = "/var/run/nginx.pid"
) -> str:
    """
    Generate main nginx.conf file with CIS Benchmark recommendations.
    
    Args:
        worker_processes: Number of worker processes
        worker_connections: Maximum connections per worker
        user: User to run NGINX as
        error_log: Path to error log
        access_log: Path to access log
        pid_file: Path to PID file
        
    Returns:
        NGINX configuration as string
    """
    return f"""# NGINX Configuration - CIS Benchmark Compliant
# Generated automatically by NGINX CIS Benchmark Automation Tool

user {user};
worker_processes {worker_processes};
pid {pid_file};

# 2.3.4 Ensure the core dump directory is secured
working_directory /var/lib/nginx;

error_log {error_log} info;

events {{
    worker_connections {worker_connections};
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # 3.1 Ensure detailed logging is enabled
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';

    access_log {access_log} main;

    # 2.5.1 Ensure server_tokens directive is set to `off`
    server_tokens off;

    # Performance settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    # 2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0
    keepalive_timeout 10;

    # 2.4.4 Ensure send_timeout is set to 10 seconds or less, but not 0
    send_timeout 10;

    # 5.2.1 Ensure timeout values for reading the client header and body are set correctly
    client_body_timeout 10;
    client_header_timeout 10;

    # 5.2.2 Ensure the maximum request body size is set correctly
    client_max_body_size 10m;

    # 5.2.3 Ensure the maximum buffer size for URIs is defined
    large_client_header_buffers 2 1k;
    client_body_buffer_size 1k;
    client_header_buffer_size 1k;

    # Gzip settings
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/rss+xml font/truetype font/opentype 
               application/vnd.ms-fontobject image/svg+xml;

    # 2.5.4 Ensure reverse proxy does not enable information disclosure
    # Hide potentially sensitive headers from upstream servers
    proxy_hide_header X-Powered-By;
    proxy_hide_header Server;
    proxy_hide_header X-AspNet-Version;
    proxy_hide_header X-AspNetMvc-Version;
    
    # 3.7 Ensure proxies pass source IP information
    # Set headers to preserve client information when proxying
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host $host;
    
    # 4.1.9 Upstream SSL configuration defaults
    # Use TLS 1.2+ and strong ciphers for upstream connections
    proxy_ssl_protocols TLSv1.2 TLSv1.3;
    proxy_ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

    # Include server blocks
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}}
"""


def generate_default_server_conf(
    server_name: str = "_",
    ssl_cert_path: str = "/etc/nginx/ssl/nginx.crt",
    ssl_key_path: str = "/etc/nginx/ssl/nginx.key",
    dhparam_path: str = "/etc/nginx/ssl/dhparam.pem",
    access_log: str = "/var/log/nginx/access.log",
    error_log: str = "/var/log/nginx/error.log"
) -> str:
    """
    Generate default server configuration with CIS Benchmark recommendations.
    
    Args:
        server_name: Server name
        ssl_cert_path: Path to SSL certificate
        ssl_key_path: Path to SSL private key
        dhparam_path: Path to DH parameters
        access_log: Path to access log
        error_log: Path to error log
        
    Returns:
        Server configuration as string
    """
    return f"""# Default Server Configuration - CIS Benchmark Compliant

# 2.4.2 Ensure requests for unknown host names are rejected
server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}}

server {{
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    http2 on;
    server_name _;
    
    ssl_certificate {ssl_cert_path};
    ssl_certificate_key {ssl_key_path};
    
    return 444;
}}

# Main server block
server {{
    # 2.4.1 Ensure NGINX only listens for network connections on authorized ports
    listen 80;
    listen [::]:80;
    server_name {server_name};

    # 4.1.1 Ensure HTTP is redirected to HTTPS
    return 301 https://$host$request_uri;
}}

server {{
    # 2.4.1 & 4.1.13 Ensure NGINX only listens on authorized ports and HTTP/2.0 is used
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    
    server_name {server_name};

    # SSL/TLS Configuration
    # 4.1.3 Ensure private key permissions are restricted (handled by file permissions)
    ssl_certificate {ssl_cert_path};
    ssl_certificate_key {ssl_key_path};

    # 4.1.4 Ensure only modern TLS protocols are used
    ssl_protocols TLSv1.2 TLSv1.3;

    # 4.1.5 Disable weak ciphers
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;

    # 4.1.6 Ensure custom Diffie-Hellman parameters are used
    ssl_dhparam {dhparam_path};

    # 4.1.12 Ensure session resumption is disabled to enable perfect forward security
    ssl_session_tickets off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # 4.1.8 Ensure HTTP Strict Transport Security (HSTS) is enabled
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 5.3.1 Ensure X-Frame-Options header is configured and enabled
    add_header X-Frame-Options "SAMEORIGIN" always;

    # 5.3.2 Ensure X-Content-Type-Options header is configured and enabled
    add_header X-Content-Type-Options "nosniff" always;

    # 5.3.3 Ensure that Content Security Policy (CSP) is enabled and configured properly
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    # Additional security headers
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # 2.5.1 Ensure server_tokens directive is set to `off`
    server_tokens off;

    # 2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0
    keepalive_timeout 10;

    # 2.4.4 Ensure send_timeout is set to 10 seconds or less, but not 0
    send_timeout 10;

    # 3.2 Ensure access logging is enabled
    access_log {access_log} main;

    # 3.3 Ensure error logging is enabled and set to the info logging level
    error_log {error_log} info;

    # 2.5.3 Ensure hidden file serving is disabled
    location ~ /\\. {{
        deny all;
        access_log off;
        log_not_found off;
    }}

    # 2.1.4 Ensure the autoindex module is disabled
    autoindex off;

    root /var/www/html;
    index index.html index.htm;

    location / {{
        # Static file serving with fallback to 404
        try_files $uri $uri/ =404;
        
        # Note: Proxy headers are configured globally in http block (CIS 3.7, 2.5.4)
        # If you need to proxy to an upstream, add:
        # proxy_pass http://your_upstream;
        # 
        # For HTTPS upstream with client certificate (CIS 4.1.9), also add:
        # proxy_ssl_certificate /etc/nginx/ssl/client.crt;
        # proxy_ssl_certificate_key /etc/nginx/ssl/client.key;
        # proxy_ssl_verify on;
    }}

    # Error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {{
        root /usr/share/nginx/html;
    }}
}}
"""


def generate_proxy_conf(
    upstream_name: str = "backend",
    upstream_servers: list = None,
    server_name: str = "proxy.example.com",
    ssl_cert_path: str = "/etc/nginx/ssl/nginx.crt",
    ssl_key_path: str = "/etc/nginx/ssl/nginx.key",
    dhparam_path: str = "/etc/nginx/ssl/dhparam.pem",
    client_cert_path: str = "/etc/nginx/ssl/client.crt"
) -> str:
    """
    Generate proxy/reverse proxy configuration with CIS recommendations.
    
    Args:
        upstream_name: Name of upstream backend
        upstream_servers: List of upstream server addresses
        server_name: Server name
        ssl_cert_path: Path to SSL certificate
        ssl_key_path: Path to SSL private key
        dhparam_path: Path to DH parameters
        client_cert_path: Path to client certificate for upstream auth
        
    Returns:
        Proxy configuration as string
    """
    if upstream_servers is None:
        upstream_servers = ["127.0.0.1:8080"]
    
    upstream_block = f"upstream {upstream_name} {{\n"
    for server in upstream_servers:
        upstream_block += f"    server {server};\n"
    upstream_block += "}\n"
    
    return f"""# Proxy Configuration - CIS Benchmark Compliant

{upstream_block}

server {{
    listen 80;
    listen [::]:80;
    server_name {server_name};

    # 4.1.1 Ensure HTTP is redirected to HTTPS
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    
    server_name {server_name};

    # SSL/TLS Configuration
    ssl_certificate {ssl_cert_path};
    ssl_certificate_key {ssl_key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_dhparam {dhparam_path};
    ssl_session_tickets off;

    # 4.1.8 HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    server_tokens off;

    location / {{
        # 3.7 Ensure proxies pass source IP information
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        # 2.5.4 Ensure the NGINX reverse proxy does not enable information disclosure
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;

        # 4.1.9 Ensure upstream server traffic is authenticated with a client certificate
        # Uncomment if using client certificates for upstream
        # proxy_ssl_certificate {client_cert_path};
        # proxy_ssl_certificate_key {ssl_key_path};
        # proxy_ssl_protocols TLSv1.2 TLSv1.3;
        # proxy_ssl_ciphers HIGH:!aNULL:!MD5;

        proxy_pass http://{upstream_name};
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
}}
"""


def generate_logrotate_conf(
    log_path: str = "/var/log/nginx/*.log"
) -> str:
    """
    Generate logrotate configuration for NGINX logs.
    
    Args:
        log_path: Path pattern for log files
        
    Returns:
        Logrotate configuration as string
    """
    return f"""# NGINX Logrotate Configuration - CIS 3.4

{log_path} {{
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 nginx adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 `cat /var/run/nginx.pid`
        fi
    endscript
}}
"""


def get_all_templates() -> Dict[str, Any]:
    """
    Get all configuration templates.
    
    Returns:
        Dictionary of template functions
    """
    return {
        'nginx_conf': generate_nginx_conf,
        'default_server': generate_default_server_conf,
        'proxy_conf': generate_proxy_conf,
        'logrotate': generate_logrotate_conf
    }

