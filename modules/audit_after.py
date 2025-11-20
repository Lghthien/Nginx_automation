import logging
import importlib
import sys
import os

# --- LOGIC IMPORT LINH HOẠT CHO CISAUDIT ---
# Class CISAudit được tải linh hoạt để tránh lỗi ImportError tĩnh
try:
    # Thử import từ file cis_audit (ngang hàng) hoặc modules.cis_audit
    cis_audit_module = importlib.import_module("cis_audit")
    CISAudit = getattr(cis_audit_module, "CISAudit")
except (ImportError, AttributeError):
    try:
        cis_audit_module = importlib.import_module("modules.cis_audit")
        CISAudit = getattr(cis_audit_module, "CISAudit")
    except Exception as e:
        # Nếu thất bại, tạo một lớp lỗi để Orchestrator vẫn chạy mà không bị crash hoàn toàn
        logging.error(f"FATAL: CISAudit class is missing: {e}")
        class CISAudit:
            def __init__(self, *args, **kwargs): pass
            def execute(self): 
                raise ImportError("CISAudit class is missing, cannot perform final audit.")
            check_count = 0
            passed_checks = 0
# ------------------------------------------

class AuditAfter:
    def __init__(self, connection_manager, logger):
        self.cm = connection_manager
        self.logger = logger
        self.check_count = 0 
        self.passed_checks = 0

    def execute(self):
        """Thực hiện Audit cuối cùng bằng cách chạy toàn bộ các kiểm tra CIS tự động."""
        try:
            self.logger.info("Performing final Post-Configuration CIS NGINX Benchmark Audit")
            
            # Khởi tạo và chạy CISAudit
            cis_auditor = CISAudit(self.cm, self.logger)
            audit_success = cis_auditor.execute()
            
            # Cập nhật kết quả tổng thể từ CISAudit
            self.check_count = cis_auditor.check_count
            self.passed_checks = cis_auditor.passed_checks
            
            compliance_rate = (self.passed_checks / self.check_count) * 100 if self.check_count > 0 else 0.0
            
            self.logger.info(f"Final CIS Compliance Rate: {compliance_rate:.1f}% ({self.passed_checks}/{self.check_count} checks passed)")
            
            # Ghi chú: File JSON đã được tạo bên trong cis_auditor.execute()
            self.logger.info("Detailed CIS audit results successfully generated.")
            
            return audit_success
            
        except Exception as e:
            self.logger.error(f"Post-configuration audit (CIS) failed unexpectedly: {str(e)}")
            return False