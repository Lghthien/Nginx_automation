import logging
import json
import os
from datetime import datetime
from typing import Dict

class ExportResults:
    def __init__(self, connection_manager, logger, total_checks, passed_checks):
        self.cm = connection_manager
        self.logger = logger
        self.total_checks = total_checks
        self.passed_checks = passed_checks

    def _load_cis_results(self, filename: str) -> Dict:
        """Tải kết quả chi tiết từ file JSON tạm thời"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"CIS results file not found: {filename}")
            return {}
        except Exception as e:
            self.logger.error(f"Error loading CIS results from {filename}: {e}")
            return {}

    def execute(self):
        """Xuất kết quả ra file với dữ liệu thực tế"""
        try:
            self.logger.info("Exporting consolidated results")

            if not os.path.exists('results'):
                os.makedirs('results')

            # --- Thu thập kết quả CIS ---
            cis_audit_results = self._load_cis_results("cis_audit_results.json")
            cis_manual_results = self._load_cis_results("cis_manual_results.json")

            # Tính toán compliance rate (nếu có kết quả CIS)
            cis_summary = cis_audit_results.get('summary', {})
            total_checks_cis = cis_summary.get('total_checks', 0)
            passed_checks_cis = cis_summary.get('passed', 0)
            
            compliance_rate = (passed_checks_cis / total_checks_cis) * 100 if total_checks_cis > 0 else 0

            # Tạo filename với timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            hostname = self.cm.host.replace('.', '_') if hasattr(self.cm, 'host') else 'localhost'
            filename = f"results/nginx_cis_report_{hostname}_{timestamp}.json"

            # Kết quả chi tiết
            results = {
                'host': hostname,
                'timestamp': timestamp,
                'overall_compliance_rate': round(compliance_rate, 1),
                'cis_audit_summary': cis_summary,
                'cis_audit_details': cis_audit_results.get('results', {}),
                'manual_checks_data': cis_manual_results,
                'modules_executed': [
                    'PrepareSystem', 'InstallNginx', 'AuditBefore', 
                    'ConfigUserPerm', 'ConfigLogging', 'ConfigSecurity',
                    'ValidateConfig', 'CISRemediate', 'RestartService', 
                    'ManualCheck', 'AuditAfter', 'ExportResults'
                ],
                'recommendations': self._generate_recommendations(compliance_rate)
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Results exported to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {str(e)}")
            return False
    
    def _generate_recommendations(self, compliance_rate):
        """Tạo recommendations dựa trên compliance rate và kết quả Manual Check"""
        recommendations = []
        if compliance_rate < 90:
            recommendations.append("Review all FAILED checks in the 'cis_audit_details' section for immediate remediation.")
        
        # Thêm khuyến nghị cho các mục thủ công
        recommendations.append("MANUAL ACTION REQUIRED: Review 'manual_checks_data' for items like Cipher Suites (4.1.5), HTTP-to-HTTPS Redirection (4.1.1), and IP Access Control (5.1.1) which require administrative verification or specific environment values.")
        
        return recommendations