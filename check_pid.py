#!/usr/bin/env python3
from managers.connection_manager import ConnectionManager

cm = ConnectionManager('192.168.127.144', 'testnginx', '110676')
cm.connect()

# Check PID file details
rc, output, _ = cm.exec_command('stat /run/nginx.pid 2>/dev/null', sudo=True)
print('PID file stat:')
print(output)

# Check ownership
rc, owner, _ = cm.exec_command('stat -L -c "%U:%G" /run/nginx.pid 2>/dev/null', sudo=True)
print('Ownership:', owner.strip())

# Check permissions
rc, perms, _ = cm.exec_command('stat -L -c "%a" /run/nginx.pid 2>/dev/null', sudo=True)
print('Permissions:', perms.strip())

cm.close()
