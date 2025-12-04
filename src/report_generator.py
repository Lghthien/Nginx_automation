"""Report Generator for CIS Benchmark results."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.models import ReportData, HostResult


class ReportGenerator:
    """Generate reports from CIS Benchmark check results."""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize Report Generator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        self.logger = logging.getLogger("nginx_cis.report")
        
        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_json(self, report_data: ReportData) -> dict:
        """
        Generate JSON report from report data.
        
        Args:
            report_data: ReportData object containing all results
            
        Returns:
            Report as dictionary
        """
        try:
            self.logger.info("Generating JSON report")
            
            report_dict = report_data.to_dict()
            
            # Add metadata
            report_dict["metadata"] = {
                "generator": "NGINX CIS Benchmark Automation Tool",
                "version": "1.0.0",
                "generated_at": report_data.timestamp
            }
            
            self.logger.info(f"Report generated with {report_dict['summary']['total_checks']} checks across {report_dict['summary']['total_hosts']} hosts")
            
            return report_dict
            
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            raise
    
    def save_report(self, report_data: ReportData, filename: Optional[str] = None) -> str:
        """
        Save report to file.
        
        Args:
            report_data: ReportData object containing all results
            filename: Optional filename (auto-generated if not provided)
            
        Returns:
            Path to saved report file
        """
        try:
            # Generate report dictionary
            report_dict = self.generate_json(report_data)
            
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"nginx_cis_report_{timestamp}.json"
            
            # Ensure .json extension
            if not filename.endswith('.json'):
                filename += '.json'
            
            # Full path
            report_path = Path(self.output_dir) / filename
            
            # Save to file
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Report saved to {report_path}")
            
            return str(report_path)
            
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")
            raise
    
    def print_summary(self, report_data: ReportData) -> None:
        """
        Print a summary of the report to console.
        
        Args:
            report_data: ReportData object containing all results
        """
        try:
            summary = report_data.get_summary()
            
            print("\n" + "="*80)
            print("NGINX CIS BENCHMARK - SUMMARY REPORT")
            print("="*80)
            print(f"Timestamp: {report_data.timestamp}")
            print(f"\nTotal Hosts: {summary['total_hosts']}")
            print(f"  - Successful: {summary['successful_hosts']}")
            print(f"  - Failed: {summary['failed_hosts']}")
            print(f"\nTotal Checks: {summary['total_checks']}")
            print(f"  - Passed: {summary['passed']} ({self._percentage(summary['passed'], summary['total_checks'])})")
            print(f"  - Failed: {summary['failed']} ({self._percentage(summary['failed'], summary['total_checks'])})")
            print(f"  - Warnings: {summary['warnings']} ({self._percentage(summary['warnings'], summary['total_checks'])})")
            print(f"  - Errors: {summary['errors']} ({self._percentage(summary['errors'], summary['total_checks'])})")
            
            print("\n" + "-"*80)
            print("HOST DETAILS")
            print("-"*80)
            
            for host in report_data.hosts:
                host_summary = host.get_summary()
                status_symbol = "✓" if host.status == "success" else "✗"
                
                print(f"\n{status_symbol} {host.hostname} ({host.ip})")
                print(f"  Status: {host.status.upper()}")
                
                if host.error_message:
                    print(f"  Error: {host.error_message}")
                
                if host_summary['total'] > 0:
                    print(f"  Checks: {host_summary['total']}")
                    print(f"    - Passed: {host_summary['passed']} ({self._percentage(host_summary['passed'], host_summary['total'])})")
                    print(f"    - Failed: {host_summary['failed']} ({self._percentage(host_summary['failed'], host_summary['total'])})")
                    print(f"    - Warnings: {host_summary['warnings']} ({self._percentage(host_summary['warnings'], host_summary['total'])})")
                    
                    # Show failed checks
                    failed_checks = [c for c in host.checks if c.status.value == "FAIL"]
                    if failed_checks:
                        print(f"\n  Failed Checks:")
                        for check in failed_checks[:5]:  # Show first 5
                            print(f"    - {check.check_id}: {check.name}")
                        
                        if len(failed_checks) > 5:
                            print(f"    ... and {len(failed_checks) - 5} more")
            
            print("\n" + "="*80)
            
        except Exception as e:
            self.logger.error(f"Failed to print summary: {e}")
    
    def _percentage(self, value: int, total: int) -> str:
        """
        Calculate percentage.
        
        Args:
            value: Numerator
            total: Denominator
            
        Returns:
            Formatted percentage string
        """
        if total == 0:
            return "0.0%"
        return f"{(value / total * 100):.1f}%"
    
    def generate_host_report(self, host_result: HostResult, filename: Optional[str] = None) -> str:
        """
        Generate report for a single host.
        
        Args:
            host_result: HostResult object
            filename: Optional filename
            
        Returns:
            Path to saved report file
        """
        try:
            # Create a ReportData with single host
            report_data = ReportData(
                timestamp=datetime.now().isoformat(),
                hosts=[host_result]
            )
            
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_hostname = host_result.hostname.replace(" ", "_").replace(".", "_")
                filename = f"nginx_cis_{safe_hostname}_{timestamp}.json"
            
            return self.save_report(report_data, filename)
            
        except Exception as e:
            self.logger.error(f"Failed to generate host report: {e}")
            raise
    
    def export_csv_summary(self, report_data: ReportData, filename: Optional[str] = None) -> str:
        """
        Export summary as CSV file.
        
        Args:
            report_data: ReportData object
            filename: Optional filename
            
        Returns:
            Path to saved CSV file
        """
        try:
            import csv
            
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"nginx_cis_summary_{timestamp}.csv"
            
            csv_path = Path(self.output_dir) / filename
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    "Hostname", "IP", "Status", "Total Checks",
                    "Passed", "Failed", "Warnings", "Errors"
                ])
                
                # Write host data
                for host in report_data.hosts:
                    summary = host.get_summary()
                    writer.writerow([
                        host.hostname,
                        host.ip,
                        host.status,
                        summary['total'],
                        summary['passed'],
                        summary['failed'],
                        summary['warnings'],
                        summary['errors']
                    ])
            
            self.logger.info(f"CSV summary exported to {csv_path}")
            return str(csv_path)
            
        except Exception as e:
            self.logger.error(f"Failed to export CSV: {e}")
            raise

