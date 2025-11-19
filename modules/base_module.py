# import logging
# from abc import ABC, abstractmethod
# from typing import Dict, Any, Tuple

# class BaseModule(ABC):
#     """Lớp cơ sở cho tất cả các module automation"""
    
#     def __init__(self, connection_manager, result_manager, config):
#         self.connection_manager = connection_manager
#         self.result_manager = result_manager
#         self.config = config
#         self.logger = logging.getLogger(self.__class__.__name__)
#         self.module_name = self.__class__.__name__
    
#     @abstractmethod
#     def execute(self) -> bool:
#         """Phương thức chính để thực thi module - Phải được triển khai bởi lớp con"""
#         pass
    
#     def run_command(self, command: str, sudo: bool = False) -> Tuple[bool, str]:
#         """Chạy lệnh trên máy từ xa"""
#         return self.connection_manager.run_command(command, sudo)
    
#     def check_command_exists(self, command: str) -> bool:
#         """Kiểm tra xem lệnh có tồn tại không"""
#         success, _ = self.run_command(f"command -v {command}")
#         return success
    
#     def backup_file(self, file_path: str) -> bool:
#         """Sao lưu file cấu hình"""
#         if not self.config.backup_config:
#             return True
            
#         backup_path = f"{file_path}.backup"
#         success, _ = self.run_command(f"cp {file_path} {backup_path}", sudo=True)
        
#         if success:
#             self.logger.info(f"Backed up {file_path} to {backup_path}")
#             return True
#         else:
#             self.logger.error(f"Failed to backup {file_path}")
#             return False
    
#     def file_exists(self, file_path: str) -> bool:
#         """Kiểm tra file có tồn tại không"""
#         success, _ = self.run_command(f"test -f {file_path} && echo 'exists'")
#         return success
    
#     def directory_exists(self, dir_path: str) -> bool:
#         """Kiểm tra thư mục có tồn tại không"""
#         success, _ = self.run_command(f"test -d {dir_path} && echo 'exists'")
#         return success
    
#     def add_cis_result(self, check_id: str, status: str, message: str, level: int = None):
#         """Thêm kết quả kiểm tra CIS"""
#         from config import CIS_BENCHMARKS
        
#         if check_id in CIS_BENCHMARKS:
#             benchmark = CIS_BENCHMARKS[check_id]
#             description = benchmark['description']
#             check_level = level or benchmark['level']
            
#             self.result_manager.add_result(
#                 check_id=check_id,
#                 description=description,
#                 status=status,
#                 message=message,
#                 module=self.module_name,
#                 level=check_level
#             )
#         else:
#             self.logger.warning(f"Unknown CIS check ID: {check_id}")