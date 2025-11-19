import json
import datetime
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

@dataclass
class CheckResult:
    check_id: str
    description: str
    status: str  # PASS, FAIL, ERROR, SKIPPED
    message: str
    timestamp: str
    module: str
    level: int
    host: str

class ResultManager:
    """Quản lý kết quả kiểm tra và báo cáo"""
    
    def __init__(self, host: str):
        self.host = host
        self.results: List[CheckResult] = []
        self.start_time = datetime.datetime.now()
    
    def add_result(self, check_id: str, description: str, status: str, 
                  message: str, module: str, level: int = 2):
        """Thêm kết quả kiểm tra"""
        result = CheckResult(
            check_id=check_id,
            description=description,
            status=status,
            message=message,
            timestamp=datetime.datetime.now().isoformat(),
            module=module,
            level=level,
            host=self.host
        )
        self.results.append(result)
    
    def get_summary(self) -> Dict[str, Any]:
        """Lấy tổng kết kết quả"""
        total = len(self.results)
        pass_count = len([r for r in self.results if r.status == 'PASS'])
        fail_count = len([r for r in self.results if r.status == 'FAIL'])
        error_count = len([r for r in self.results if r.status == 'ERROR'])
        skipped_count = len([r for r in self.results if r.status == 'SKIPPED'])
        
        return {
            'host': self.host,
            'total': total,
            'pass': pass_count,
            'fail': fail_count,
            'error': error_count,
            'skipped': skipped_count,
            'pass_rate': (pass_count / total * 100) if total > 0 else 0,
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.datetime.now().isoformat(),
            'duration': (datetime.datetime.now() - self.start_time).total_seconds()
        }
    
    def get_results_by_level(self, level: int) -> List[CheckResult]:
        """Lấy kết quả theo CIS level"""
        return [r for r in self.results if r.level == level]
    
    def get_results_by_status(self, status: str) -> List[CheckResult]:
        """Lấy kết quả theo trạng thái"""
        return [r for r in self.results if r.status == status]
    
    def export_json(self, filepath: str):
        """Xuất kết quả dạng JSON"""
        import os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        data = {
            'host': self.host,
            'summary': self.get_summary(),
            'results': [asdict(r) for r in self.results]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)