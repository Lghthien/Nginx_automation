#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from managers.connection_manager import ConnectionManager
import logging

logging.basicConfig(level=logging.WARNING)

cm = ConnectionManager('192.168.127.144', 'testnginx', '110676')

# Check what's in the catchall file
print("=== File listing in /etc/nginx/conf.d/ ===")
rc, out, err = cm.exec_command("ls -la /etc/nginx/conf.d/", sudo=True)
print(out)

print("\n=== Content of catchall.conf ===")
rc, out, err = cm.exec_command("cat /etc/nginx/conf.d/catchall.conf", sudo=True)
print(f"RC: {rc}")
print(f"Content:\n{out}")

print("\n=== Grep for 'return 444' ===")
rc, out, err = cm.exec_command("grep -ir 'return 444' /etc/nginx/conf.d/", sudo=True)
print(f"RC: {rc}")
print(f"Output: {out}")
print(f"Error: {err}")

print("\n=== Grep for 'return' (any) ===")
rc, out, err = cm.exec_command("grep -ir 'return' /etc/nginx/conf.d/", sudo=True)
print(f"RC: {rc}")
print(f"Output: {out}")

cm.close()
