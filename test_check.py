#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from managers.connection_manager import ConnectionManager
from modules.cis_audit import CISAudit
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

cm = ConnectionManager('192.168.127.144', 'testnginx', '110676')
audit = CISAudit(cm, logger)

# Test check 2.4.2
result, msg = audit._check_2_4_2_unknown_hosts()
print(f"2.4.2 Result: {result}")
print(f"2.4.2 Message: {msg}")

# List what's in conf.d
rc, output, err = cm.exec_command("ls -la /etc/nginx/conf.d/ 2>&1", sudo=True)
print(f"\nFiles in /etc/nginx/conf.d/:")
print(output)

# Check if catchall exists
rc, output, err = cm.exec_command("grep -r 'return 444' /etc/nginx/conf.d/ 2>&1", sudo=True)
print(f"\nGrep 'return 444' (rc={rc}):")
print(f"Output: {output}")
print(f"Error: {err}")
