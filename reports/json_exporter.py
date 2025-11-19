import json
import os
from typing import Dict, Any, List
from datetime import datetime
from ..managers.result_manager import CheckResult

class JSONExporter:
    """JSON exporter for CIS benchmark results"""
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def export_single_host(self, result_manager, output_file: str):
        """Export results for a single host to JSON"""
        data = self._prepare_single_host_data(result_manager)
        self._write_json(data, output_file)
    
    def export_consolidated(self, all_results: Dict[str, Any], output_file: str):
        """Export consolidated results for all hosts to JSON"""
        data = self._prepare_consolidated_data(all_results)
        self._write_json(data, output_file)
    
    def _prepare_single_host_data(self, result_manager) -> Dict[str, Any]:
        """Prepare data structure for single host"""
        summary = result_manager.get_summary()
        
        return {
            "metadata": {
                "generated_at": self.timestamp,
                "cis_level": getattr(result_manager, 'cis_level', 2),
                "tool_version": "1.0.0",
                "host": result_manager.host
            },
            "summary": {
                "host": summary['host'],
                "total_checks": summary['total'],
                "passed_checks": summary['pass'],
                "failed_checks": summary['fail'],
                "error_checks": summary['error'],
                "skipped_checks": summary['skipped'],
                "compliance_rate": round(summary['pass_rate'], 2),
                "start_time": summary['start_time'],
                "end_time": summary['end_time'],
                "duration_seconds": round(summary['duration'], 2)
            },
            "results": self._format_results(result_manager.results),
            "compliance_by_level": self._calculate_compliance_by_level(result_manager.results),
            "recommendations": self._generate_recommendations(result_manager.results)
        }
    
    def _prepare_consolidated_data(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data structure for multiple hosts"""
        hosts_data = {}
        overall_summary = {
            "total_hosts": len(all_results),
            "total_checks": 0,
            "passed_checks": 0,
            "failed_checks": 0,
            "error_checks": 0,
            "skipped_checks": 0,
            "hosts_compliance": {}
        }
        
        for host, result_manager in all_results.items():
            host_data = self._prepare_single_host_data(result_manager)
            hosts_data[host] = host_data
            
            # Update overall summary
            summary = host_data['summary']
            overall_summary['total_checks'] += summary['total_checks']
            overall_summary['passed_checks'] += summary['passed_checks']
            overall_summary['failed_checks'] += summary['failed_checks']
            overall_summary['error_checks'] += summary['error_checks']
            overall_summary['skipped_checks'] += summary['skipped_checks']
            overall_summary['hosts_compliance'][host] = summary['compliance_rate']
        
        # Calculate overall compliance
        if overall_summary['total_checks'] > 0:
            overall_compliance = (overall_summary['passed_checks'] / overall_summary['total_checks']) * 100
        else:
            overall_compliance = 0
            
        overall_summary['overall_compliance_rate'] = round(overall_compliance, 2)
        
        return {
            "metadata": {
                "generated_at": self.timestamp,
                "cis_level": 2,  # Assuming all hosts use same level
                "tool_version": "1.0.0",
                "total_hosts": len(all_results)
            },
            "overall_summary": overall_summary,
            "hosts": hosts_data,
            "comparative_analysis": self._generate_comparative_analysis(hosts_data)
        }
    
    def _format_results(self, results: List[CheckResult]) -> List[Dict[str, Any]]:
        """Format results for JSON output"""
        formatted_results = []
        
        for result in results:
            formatted_result = {
                "check_id": result.check_id,
                "description": result.description,
                "status": result.status,
                "level": result.level,
                "module": result.module,
                "timestamp": result.timestamp,
                "message": result.message,
                "severity": self._determine_severity(result.status)
            }
            formatted_results.append(formatted_result)
        
        return formatted_results
    
    def _calculate_compliance_by_level(self, results: List[CheckResult]) -> Dict[str, Any]:
        """Calculate compliance statistics by CIS level"""
        level_stats = {}
        
        for level in [1, 2]:
            level_checks = [r for r in results if r.level == level]
            total = len(level_checks)
            passed = len([r for r in level_checks if r.status == 'PASS'])
            
            if total > 0:
                compliance_rate = (passed / total) * 100
            else:
                compliance_rate = 0
            
            level_stats[f"level_{level}"] = {
                "total_checks": total,
                "passed_checks": passed,
                "compliance_rate": round(compliance_rate, 2),
                "failed_checks": len([r for r in level_checks if r.status == 'FAIL']),
                "checks": [
                    {
                        "check_id": r.check_id,
                        "status": r.status,
                        "description": r.description
                    } for r in level_checks
                ]
            }
        
        return level_stats
    
    def _generate_recommendations(self, results: List[CheckResult]) -> Dict[str, Any]:
        """Generate recommendations based on failed checks"""
        failed_checks = [r for r in results if r.status == 'FAIL']
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for check in failed_checks:
            recommendation = {
                "check_id": check.check_id,
                "description": check.description,
                "message": check.message,
                "level": check.level,
                "remediation": self._get_remediation_steps(check.check_id)
            }
            
            # Priority based on CIS level and check type
            if check.level == 1:
                high_priority.append(recommendation)
            elif '2.1.' in check.check_id or '4.1.' in check.check_id:
                high_priority.append(recommendation)
            else:
                medium_priority.append(recommendation)
        
        return {
            "high_priority": high_priority,
            "medium_priority": medium_priority,
            "low_priority": low_priority,
            "total_recommendations": len(high_priority) + len(medium_priority) + len(low_priority)
        }
    
    def _generate_comparative_analysis(self, hosts_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comparative analysis across all hosts"""
        compliance_rates = {}
        common_failures = {}
        
        for host, data in hosts_data.items():
            compliance_rates[host] = data['summary']['compliance_rate']
            
            # Track common failures
            for result in data['results']:
                if result['status'] == 'FAIL':
                    check_id = result['check_id']
                    if check_id not in common_failures:
                        common_failures[check_id] = {
                            'description': result['description'],
                            'affected_hosts': [],
                            'count': 0
                        }
                    common_failures[check_id]['affected_hosts'].append(host)
                    common_failures[check_id]['count'] += 1
        
        # Sort by most common failures
        sorted_failures = dict(sorted(
            common_failures.items(), 
            key=lambda x: x[1]['count'], 
            reverse=True
        ))
        
        return {
            "compliance_rates": compliance_rates,
            "average_compliance": round(sum(compliance_rates.values()) / len(compliance_rates), 2),
            "most_compliant_host": max(compliance_rates, key=compliance_rates.get),
            "least_compliant_host": min(compliance_rates, key=compliance_rates.get),
            "common_failures": sorted_failures,
            "top_failures": dict(list(sorted_failures.items())[:5])  # Top 5 failures
        }
    
    def _determine_severity(self, status: str) -> str:
        """Determine severity based on check status"""
        severity_map = {
            'PASS': 'low',
            'FAIL': 'high',
            'ERROR': 'critical',
            'SKIPPED': 'info'
        }
        return severity_map.get(status, 'medium')
    
    def _get_remediation_steps(self, check_id: str) -> str:
        """Get remediation steps for a specific check"""
        remediation_map = {
            '2.1.2': "Recompile NGINX without the --with-http_dav_module flag",
            '2.1.3': "Recompile NGINX without gzip modules or disable them in configuration",
            '2.1.4': "Set 'autoindex off;' in NGINX configuration files",
            '2.2.1': "Create dedicated nginx user and set 'user nginx;' in nginx.conf",
            '2.4.3': "Add 'keepalive_timeout 10;' to NGINX configuration",
            '2.5.1': "Add 'server_tokens off;' to NGINX configuration",
            '4.1.12': "Add 'ssl_session_tickets off;' to SSL configuration",
            '4.1.13': "Add 'http2' to listen directives for SSL ports"
        }
        return remediation_map.get(check_id, "Refer to CIS NGINX Benchmark documentation for remediation steps")
    
    def _write_json(self, data: Dict[str, Any], output_file: str):
        """Write data to JSON file"""
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"JSON report generated: {output_file}")

# Convenience functions
def generate_json_report(result_manager, output_file: str):
    """Generate JSON report for single host"""
    exporter = JSONExporter()
    exporter.export_single_host(result_manager, output_file)

def generate_consolidated_json_report(all_results: Dict[str, Any], output_file: str):
    """Generate consolidated JSON report for multiple hosts"""
    exporter = JSONExporter()
    exporter.export_consolidated(all_results, output_file)