import logging
import json
import os
from datetime import datetime

class ExportResults:
    def __init__(self, connection_manager, logger, total_checks, passed_checks):
        self.cm = connection_manager
        self.logger = logger
        self.total_checks = total_checks
        self.passed_checks = passed_checks

    def execute(self):
        """Xuất kết quả ra file với dữ liệu thực tế"""
        try:
            self.logger.info("Exporting results")

            # Tạo thư mục results nếu chưa tồn tại
            if not os.path.exists('results'):
                os.makedirs('results')

            # Thu thập dữ liệu thực tế
            nginx_version = self._get_nginx_version()
            service_status = self._get_service_status()
            config_status = self._get_config_status()
            security_headers = self._check_security_headers()

            # Tính toán compliance rate thực tế
            total_checks = self.total_checks
            passed_checks = self.passed_checks
            compliance_rate = (passed_checks / total_checks) * 100 if total_checks > 0 else 0

            # Tạo filename với timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            hostname = self.cm.host.replace('.', '_')
            filename = f"results/nginx_audit_{hostname}_{timestamp}.json"

            # Kết quả chi tiết
            results = {
                'host': self.cm.host,
                'timestamp': timestamp,
                'compliance_rate': round(compliance_rate, 1),
                'checks_passed': passed_checks,
                'total_checks': total_checks,
                'summary': {
                    'nginx_version': nginx_version,
                    'service_status': service_status,
                    'config_status': config_status,
                    'security_headers': security_headers
                },
                'modules_executed': [
                    'PrepareSystem',
                    'InstallNginx',
                    'AuditBefore',
                    'ConfigSecurity', 
                    'ConfigUserPerm',
                    'ConfigLogging',
                    'ValidateConfig',
                    'RestartService',
                    'AuditAfter'
                ],
                'recommendations': self._generate_recommendations(compliance_rate)
            }
            
            # Ghi ra file
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Results exported to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {str(e)}")
            return False
    
    def _get_nginx_version(self):
        """Lấy version NGINX"""
        try:
            exit_status, output, error = self.cm.exec_command('nginx -v 2>&1')
            return output.strip() if exit_status == 0 else "Unknown"
        except:
            return "Unknown"
    
    def _get_service_status(self):
        """Lấy trạng thái dịch vụ"""
        try:
            exit_status, output, error = self.cm.exec_command('systemctl is-active nginx', sudo=True)
            status = output.strip() if exit_status == 0 else "Unknown"
            
            # Lấy thêm thông tin chi tiết
            exit_status, output, error = self.cm.exec_command('systemctl status nginx --no-pager', sudo=True)
            details = output.strip() if exit_status == 0 else "No details"
            
            return {
                'status': status,
                'details': details[:500]  # Giới hạn độ dài
            }
        except:
            return {'status': 'Unknown', 'details': 'Error fetching status'}
    
    def _get_config_status(self):
        """Lấy trạng thái config"""
        try:
            exit_status, output, error = self.cm.exec_command('nginx -t 2>&1', sudo=True)
            if exit_status == 0:
                return {
                    'status': 'Valid',
                    'details': output.strip()
                }
            else:
                return {
                    'status': 'Invalid', 
                    'details': error.strip() or output.strip()
                }
        except:
            return {'status': 'Unknown', 'details': 'Error testing config'}
    
    def _check_security_headers(self):
        """Kiểm tra security headers"""
        try:
            # Kiểm tra các security settings cơ bản
            checks = {}
            
            # Check server tokens
            exit_status, output, error = self.cm.exec_command('grep "server_tokens" /etc/nginx/nginx.conf', sudo=True)
            checks['server_tokens'] = 'off' in output if exit_status == 0 else 'Unknown'
            
            # Check if security config file exists
            exit_status, output, error = self.cm.exec_command('ls /etc/nginx/conf.d/security.conf', sudo=True)
            checks['security_config'] = exit_status == 0
            
            return checks
        except:
            return {'error': 'Could not check security headers'}
    
    def _generate_recommendations(self, compliance_rate):
        """Tạo recommendations dựa trên compliance rate"""
        recommendations = []
        
        if compliance_rate < 90:
            recommendations.append("Improve file permissions handling for configuration changes")
            recommendations.append("Consider using configuration management tools for better reliability")
        
        if compliance_rate >= 80:
            recommendations.append("Good overall compliance - maintain current practices")
        
        if compliance_rate >= 90:
            recommendations.append("Excellent compliance - consider advanced security hardening")
        
        recommendations.append("Regularly update NGINX to the latest stable version")
        recommendations.append("Monitor logs for security events and performance issues")
        
        return recommendations