import logging
import sys
import os
from datetime import datetime
import click

# Custom logging handler để fix lỗi emoji trên Windows
class SafeStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            # Thay thế emoji bằng text cho Windows
            emoji_replacements = {
                '🔧': '[TOOL]',
                '🚀': '[START]',
                '✅': '[OK]',
                '❌': '[ERROR]',
                '⚠️': '[WARN]',
                '📊': '[REPORT]',
                '🎯': '[TARGET]',
                '🛠️': '[CONFIG]'
            }
            for emoji, text in emoji_replacements.items():
                msg = msg.replace(emoji, text)
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except UnicodeEncodeError:
            # Fallback: bỏ qua ký tự không hiển thị được
            msg = self.format(record).encode('ascii', 'ignore').decode('ascii')
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

def setup_logging():
    """Thiết lập logging với handler an toàn cho Windows"""
    handler = SafeStreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Xóa handler cũ nếu có
    for h in logger.handlers[:]:
        logger.removeHandler(h)
    
    logger.addHandler(handler)

from managers.connection_manager import ConnectionManager
from managers.orchestrator import Orchestrator

@click.command()
@click.option('-h', '--hosts', multiple=True, required=True, help='Target host(s)')
@click.option('-u', '--username', default=None, help='SSH username')
@click.option('-p', '--password', default=None, help='SSH password')
@click.option('--key-file', default=None, help='SSH private key file')
def main(hosts, username, password, key_file):
    """NGINX CIS Automation Tool - Level 2"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting NGINX CIS Automation Tool - Level 2")
        logger.info(f"Target hosts: {list(hosts)}")
        
        all_summaries = []
        
        for host in hosts:
            logger.info(f"[TOOL] Processing host: {host}")
            
            # Kết nối đến host
            conn_manager = ConnectionManager(host, username, password, key_file)
            if not conn_manager.connect():
                logger.error(f"[ERROR] Cannot connect to {host}, skipping")
                continue
                
            # Thực thi các module
            orchestrator = Orchestrator(conn_manager)
            success, summary = orchestrator.run()
            
            if success:
                logger.info(f"[OK] Host {host} completed: {summary['pass']}/{summary['total']} checks passed")
            else:
                logger.warning(f"[WARN] Host {host} completed with warnings: {summary['pass']}/{summary['total']} checks passed")
            
            all_summaries.append(summary)
            conn_manager.close()
        
        # Tạo báo cáo tổng
        if all_summaries:
            total_checks = sum(s['total'] for s in all_summaries)
            total_passed = sum(s['pass'] for s in all_summaries)
            overall_compliance = (total_passed / total_checks) * 100 if total_checks > 0 else 0
            
            logger.info("[REPORT] Individual host reports generated in 'results/' directory")
            logger.info(f"[TARGET] OVERALL SUMMARY: {overall_compliance:.1f}% compliance ({total_passed}/{total_checks} checks passed across {len(hosts)} hosts)")
            
            if overall_compliance < 80:
                logger.warning("[WARN] Low compliance level - review required")
            else:
                logger.info("[OK] Good compliance level achieved")
                
        return 0
        
    except Exception as e:
        logger.error(f"[ERROR] Script execution failed: {str(e)}")
        return 1

if __name__ == '__main__':
    main()