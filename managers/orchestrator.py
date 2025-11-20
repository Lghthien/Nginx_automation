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
        
        # Danh sách các module theo thứ tự logic đã được điều chỉnh
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
            'audit_after',      # FINAL AUDIT (Tạo cis_audit_results.json)
            'export_results'    # BÁO CÁO CUỐI CÙNG (Đọc tất cả dữ liệu)
        ]
    
    def _cleanup_temp_files(self):
        """Xóa các file JSON tạm thời sau khi chạy"""
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
                
                # Truyền tham số cho ExportResults (Module cuối cùng)
                if module_file == 'export_results':
                     module = module_class(self.connection_manager, self.logger, total_checks, passed_checks)
                else:
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
        
        # --- BƯỚC KẾT THÚC VÀ TỔNG KẾT ---
        
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
        """Đảm bảo tên lớp khớp (CISRemediate, ManualCheck)"""
        if snake_str == 'cis_remediate':
             return 'CISRemediate'
        if snake_str == 'manual_check':
             return 'ManualCheck'
        if snake_str == 'audit_after':
             return 'AuditAfter'
        if snake_str == 'export_results':
             return 'ExportResults'
             
        components = snake_str.split('_')
        return ''.join(x.title() for x in components)
    
    def _import_module(self, module_file, class_name):
        """FIX LỖI PATH: Thử cả 2 đường dẫn (flat và modules/)"""
        # Thử 1: Import từ thư mục hiện tại (ngang hàng)
        try:
            module = importlib.import_module(module_file) 
            return getattr(module, class_name)
        except ImportError:
            # Thử 2: Import từ thư mục 'modules' (cấu trúc phổ biến)
            try:
                module = importlib.import_module(f'modules.{module_file}') 
                return getattr(module, class_name)
            except Exception as e:
                self.logger.error(f"Cannot import module {module_file} (tried flat and modules/): {e}")
                return None
        except AttributeError as e:
            self.logger.error(f"Cannot find class {class_name} in module {module_file}: {e}")
            return None