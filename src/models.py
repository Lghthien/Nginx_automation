"""Data models for NGINX CIS Benchmark automation."""

from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum


class CheckStatus(Enum):
    """Status of a benchmark check."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"
    NOT_APPLICABLE = "N/A"


@dataclass
class HostConfig:
    """Configuration for a remote host."""
    hostname: str
    ip: str
    username: str
    port: int = 22
    password: Optional[str] = None
    private_key: Optional[str] = None
    
    def __post_init__(self):
        """Validate that either password or private_key is provided."""
        if not self.password and not self.private_key:
            raise ValueError(f"Host {self.hostname}: Either password or private_key must be provided")
    
    def __repr__(self):
        """String representation without sensitive data."""
        return f"HostConfig(hostname={self.hostname}, ip={self.ip}, port={self.port}, username={self.username})"


@dataclass
class BenchmarkResult:
    """Result of a single benchmark check."""
    check_id: str
    name: str
    status: CheckStatus
    details: str = ""
    remediation: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.check_id,
            "name": self.name,
            "status": self.status.value,
            "details": self.details,
            "remediation": self.remediation
        }


@dataclass
class HostResult:
    """Results for a single host."""
    hostname: str
    ip: str
    status: str  # "success" or "failed"
    checks: List[BenchmarkResult] = field(default_factory=list)
    error_message: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "status": self.status,
            "error_message": self.error_message,
            "checks": [check.to_dict() for check in self.checks]
        }
    
    def get_summary(self) -> dict:
        """Get summary statistics for this host."""
        summary = {
            "total": len(self.checks),
            "passed": sum(1 for c in self.checks if c.status == CheckStatus.PASS),
            "failed": sum(1 for c in self.checks if c.status == CheckStatus.FAIL),
            "warnings": sum(1 for c in self.checks if c.status == CheckStatus.WARNING),
            "errors": sum(1 for c in self.checks if c.status == CheckStatus.ERROR),
            "not_applicable": sum(1 for c in self.checks if c.status == CheckStatus.NOT_APPLICABLE)
        }
        return summary


@dataclass
class ReportData:
    """Complete report data for all hosts."""
    timestamp: str
    hosts: List[HostResult] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        summary = self.get_summary()
        return {
            "timestamp": self.timestamp,
            "summary": summary,
            "hosts": [host.to_dict() for host in self.hosts]
        }
    
    def get_summary(self) -> dict:
        """Get overall summary statistics."""
        total_checks = sum(len(host.checks) for host in self.hosts)
        total_passed = sum(host.get_summary()["passed"] for host in self.hosts)
        total_failed = sum(host.get_summary()["failed"] for host in self.hosts)
        total_warnings = sum(host.get_summary()["warnings"] for host in self.hosts)
        total_errors = sum(host.get_summary()["errors"] for host in self.hosts)
        
        return {
            "total_hosts": len(self.hosts),
            "successful_hosts": sum(1 for h in self.hosts if h.status == "success"),
            "failed_hosts": sum(1 for h in self.hosts if h.status == "failed"),
            "total_checks": total_checks,
            "passed": total_passed,
            "failed": total_failed,
            "warnings": total_warnings,
            "errors": total_errors
        }

