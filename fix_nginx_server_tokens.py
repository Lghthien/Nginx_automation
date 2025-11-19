import paramiko
import sys

# Usage: python fix_nginx_server_tokens.py <host> <username> <password>
# Example: python fix_nginx_server_tokens.py 192.168.127.143 ngnix 110676

def fix_server_tokens(host, username, password, conf_path='/etc/nginx/conf.d/security.conf'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=username, password=password)
        print(f"[INFO] Connected to {host}")
        # Read the config file
        sftp = ssh.open_sftp()
        try:
            with sftp.open(conf_path, 'r') as f:
                lines = f.readlines()
        except IOError:
            print(f"[ERROR] Cannot open {conf_path}")
            return
        # Remove duplicate server_tokens, keep only the first
        new_lines = []
        found = False
        for line in lines:
            if 'server_tokens' in line and not found:
                new_lines.append(line)
                found = True
            elif 'server_tokens' in line and found:
                print(f"[INFO] Removing duplicate: {line.strip()}")
                continue
            else:
                new_lines.append(line)
        # Write back the file (overwrite)
        with sftp.open(conf_path, 'w') as f:
            f.writelines(new_lines)
        print(f"[OK] Fixed duplicates in {conf_path}")
        # Optionally, test nginx config
        stdin, stdout, stderr = ssh.exec_command('sudo nginx -t')
        print(stdout.read().decode())
        print(stderr.read().decode())
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        ssh.close()

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python fix_nginx_server_tokens.py <host> <username> <password>")
        sys.exit(1)
    fix_server_tokens(sys.argv[1], sys.argv[2], sys.argv[3])
