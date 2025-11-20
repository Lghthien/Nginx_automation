import logging
import importlib
import sys
import os
import re

# Thêm current directory vào path để fix lỗi import
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class Orchestrator:
    def __init__(self, connection_manager):
        self.connection_manager = connection_manager
        self.logger = logging.getLogger(__name__)
        self.results = {}
        
        # SỬA LỖI #2: Đã thêm các module CIS vào pipeline theo thứ tự Logic
        self.modules = [
            'prepare_system',
            'install_nginx', 
            'audit_before',
            'config_security',
            'config_user_perm',
            'config_logging',
            'validate_config',
            'cis_remediate',    # BƯỚC KHẮC PHỤC
            'restart_service',
            'manual_check',     # THU THẬP DỮ LIỆU THỦ CÔNG
            'audit_after',      # FINAL AUDIT (CISAudit)
        ]
    
    def _cleanup_temp_files(self):
        # ... (giữ nguyên hàm cleanup)
        temp_files = ["cis_audit_results.json", "cis_manual_results.json"]
        for f in temp_files:
            try:
                os.remove(f)
                self.logger.info(f"Cleaned up temporary file: {f}")
            except OSError as e:
                self.logger.debug(f"Could not remove temporary file {f}: {e}")

    def run(self):
        """Chạy tất cả các module"""
        total_checks = 0
        passed_checks = 0
        
        for module_file in self.modules:
            try:
                module_name = self._snake_to_camel(module_file)
                self.logger.info(f"Executing module: {module_name}")
                
                module_class = self._import_module(module_file, module_name)
                if not module_class:
                    continue
                
                module = module_class(self.connection_manager, self.logger)
                success = module.execute()
                
                if hasattr(module, 'check_count') and hasattr(module, 'passed_checks'):
                    total_checks += module.check_count
                    passed_checks += module.passed_checks
                
                self.logger.info(f"Completed module: {module_name}")
                
                if not success:
                    self.logger.warning(f"Module {module_name} completed with warnings or minor errors")
                    
            except Exception as e:
                self.logger.error(f"Module {module_name} failed unexpectedly: {str(e)}")
                continue
        
        # --- BƯỚC EXPORT CUỐI CÙNG ---
        try:
            # SỬA LỖI #3: Import và gọi ExportResults với các tham số tổng hợp
            from export_results import ExportResults
            export_module = ExportResults(self.connection_manager, self.logger, total_checks, passed_checks)
            export_module.execute()
        except ImportError as e:
            self.logger.error(f"Cannot load ExportResults module: {e}")
        except Exception as e:
            self.logger.error(f"Final Export results failed: {e}")

        self._cleanup_temp_files()

        # ... (Phần tổng kết cuối cùng giữ nguyên) ...
        if total_checks == 0:
            total_checks = 1

        passed_checks = min(passed_checks, total_checks)

        summary = {
            'total': total_checks,
            'pass': passed_checks,
            'compliance': (passed_checks / total_checks * 100)
        }
        
        success = summary['compliance'] >= 90 
        return success, summary
    
    def _snake_to_camel(self, snake_str):
        """SỬA LỖI #1: Xử lý trường hợp có 3 chữ cái đầu viết hoa (CISRemediate)"""
        if snake_str in ['cis_remediate', 'manual_check', 'audit_after']:
            # Ví dụ: cis_remediate -> CISRemediate (hoặc giữ nguyên tên lớp)
            # Giả định tên lớp là CISRemediate và ManualCheck
            return ''.join([s.title() for s in snake_str.split('_') if s])
        
        # Logic CamelCase chuẩn
        components = snake_str.split('_')
        return ''.join(x.title() for x in components)
    
    def _import_module(self, module_file, class_name):
        """Import module bằng tên file"""
        try:
            # Import trực tiếp (giả định các file module nằm ngang hàng)
            module = importlib.import_module(module_file) 
            return getattr(module, class_name)
        except ImportError as e:
            # Thử import từ thư mục modules (nếu có)
            try:
                module = importlib.import_module(f'modules.{module_file}')
                return getattr(module, class_name)
            except:
                self.logger.error(f"Cannot import module {module_file} or modules.{module_file}: {e}")
                return None
        except AttributeError as e:
            self.logger.error(f"Cannot find class {class_name} in module {module_file}: {e}")
            return None