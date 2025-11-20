import logging
import importlib
import sys
import os

# Thêm current directory vào path để fix lỗi import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class Orchestrator:
    def __init__(self, connection_manager):
        self.connection_manager = connection_manager
        self.logger = logging.getLogger(__name__)
        self.results = {}
        
        # Danh sách các module sẽ chạy theo thứ tự
        self.modules = [
            'prepare_system',
            'install_nginx', 
            'audit_before',
            'config_security',
            'config_user_perm',
            'config_logging',
            'validate_config',
            'restart_service',
            'audit_after',
            'export_results',
            'cis_remediate',
            'manual_check'
        ]
    
    def run(self):
        """Chạy tất cả các module"""
        total_checks = 0
        passed_checks = 0
        
        for module_file in self.modules:
            try:
                module_name = self._snake_to_camel(module_file)
                self.logger.info(f"Executing module: {module_name}")
                
                # Import module
                module_class = self._import_module(module_file, module_name)
                if not module_class:
                    continue
                
                # Tạo instance và chạy module
                module = module_class(self.connection_manager, self.logger)
                success = module.execute()
                
                # Cập nhật kết quả
                if hasattr(module, 'check_count') and hasattr(module, 'passed_checks'):
                    total_checks += module.check_count
                    passed_checks += module.passed_checks
                
                self.logger.info(f"Completed module: {module_name}")
                
                if not success:
                    self.logger.warning(f"Module {module_name} completed with warnings")
                    
            except Exception as e:
                self.logger.error(f"Module {module_name} failed: {str(e)}")
                continue
        
        # Thử import export_results nếu có
        try:
            from modules.export_results import ExportResults
            export_module = ExportResults(self.connection_manager, self.logger, total_checks, passed_checks)
            export_module.execute()
        except ImportError as e:
            self.logger.warning(f"Cannot load module export_results: {e}")
        except Exception as e:
            self.logger.error(f"Export results failed: {e}")
        
        # Điều chỉnh total_checks để tránh chia cho 0
        if total_checks == 0:
            total_checks = 1

        # Đảm bảo passed_checks không vượt quá total_checks
        passed_checks = min(passed_checks, total_checks)

        summary = {
            'total': total_checks,
            'pass': passed_checks,
            'compliance': (passed_checks / total_checks * 100)
        }
        
        success = summary['compliance'] >= 50  # Ít nhất 50% compliance
        return success, summary
    
    def _snake_to_camel(self, snake_str):
        """Chuyển snake_case thành CamelCase"""
        components = snake_str.split('_')
        return ''.join(x.title() for x in components)
    
    def _import_module(self, module_file, class_name):
        """Import module bằng tên file"""
        try:
            module = importlib.import_module(f'modules.{module_file}')
            return getattr(module, class_name)
        except ImportError as e:
            self.logger.error(f"Cannot import module {module_file}: {e}")
            return None
        except AttributeError as e:
            self.logger.error(f"Cannot find class {class_name} in module {module_file}: {e}")
            return None