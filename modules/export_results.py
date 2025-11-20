import logging
import json
import os
from datetime import datetime
from typing import Dict, Any

class ExportResults:
    def __init__(self, connection_manager, logger, total_checks, passed_checks):
        self.cm = connection_manager
        self.logger = logger
        self.total_checks = total_checks
        self.passed_checks = passed_checks

    def _load_json_file(self, filename: str) -> Dict[str, Any]:
        """Tải kết quả chi tiết từ file JSON tạm thời"""
        try:
            full_path = os.path.join(os.getcwd(), filename)
            
            with open(full_path, 'r', encoding='utf-8') as f:
                self.logger.info(f"Successfully loaded {filename} for final report.")
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"CIS results file not found: {filename}. Report details may be missing.")
            return {}
        except Exception as e:
            self.logger.error(f"Error loading {filename}: {e}")
            return {}

    def _generate_recommendations(self, compliance_rate, manual_data):
        """Tạo các khuyến nghị dựa trên kết quả audit."""
        recommendations = []
        if compliance_rate >= 99:
            recommendations.append("Excellent compliance achieved for automated checks. Focus entirely on manual verification.")
        else:
            recommendations.append("Review FAILED checks in 'cis_audit_details' for immediate automated remediation.")

        if manual_data:
            recommendations.append("MANUAL ACTION REQUIRED: Review 'cis_manual_check_data' (e.g., Certificates, Weak Ciphers, Redirection) as these items require administrative verification.")
            
        return recommendations

    def execute(self):
        """Xuất toàn bộ kết quả chi tiết ra file báo cáo cuối cùng."""
        try:
            self.logger.info("Exporting consolidated final report.")

            # Tải Dữ liệu Chi tiết từ các file tạm thời
            cis_audit_results = self._load_json_file("cis_audit_results.json")
            cis_manual_results = self._load_json_file("cis_manual_results.json")

            cis_summary = cis_audit_results.get('summary', {})
            total_checks_cis = cis_summary.get('total_checks', 0)
            passed_checks_cis = cis_summary.get('passed', 0)
            
            compliance_rate = (passed_checks_cis / total_checks_cis) * 100 if total_checks_cis > 0 else 0

            # Tạo Báo cáo Cuối cùng
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            hostname = self.cm.host.replace('.', '_')
            filename = f"nginx_cis_report_{hostname}_{timestamp}.json"
            filepath = os.path.join('results', filename)

            if not os.path.exists('results'):
                os.makedirs('results')

            results_payload = {
                'host': hostname,
                'timestamp': timestamp,
                'overall_compliance_rate': round(compliance_rate, 1),
                'total_checks_in_pipeline': self.total_checks,
                'passed_checks_in_pipeline': self.passed_checks,
                'cis_audit_summary': cis_summary,
                'cis_audit_details': cis_audit_results.get('results', {}),
                'cis_manual_check_data': cis_manual_results,
                'modules_executed': [
                    'PrepareSystem', 'InstallNginx', 'AuditBefore', 'ConfigSecurity', 
                    'ConfigUserPerm', 'ConfigLogging', 'ValidateConfig', 
                    'CISRemediate', 'RestartService', 'ManualCheck', 
                    'AuditAfter', 'ExportResults'
                ],
                'recommendations': self._generate_recommendations(compliance_rate, cis_manual_results)
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results_payload, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Full detailed report exported to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Final Export results failed: {str(e)}")
            return False