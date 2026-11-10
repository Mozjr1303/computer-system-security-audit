"""Base class and helper utilities for security audit modules."""
from typing import Any, Dict, Optional
from app.schemas.audit_schemas import (
    AuditCategory,
    AuditCheckResult,
    CheckStatus,
    FindingType,
    SeverityLevel,
)


class BaseAuditor:
    """Base class for all Windows security audit scanners."""

    category: AuditCategory

    def make_check(
        self,
        check_id: str,
        title: str,
        description: str,
        status: CheckStatus,
        severity: SeverityLevel,
        finding_type: FindingType,
        evidence: str,
        explanation: str,
        remediation: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditCheckResult:
        """Create a standardized AuditCheckResult object."""
        return AuditCheckResult(
            check_id=check_id,
            category=self.category,
            title=title,
            description=description,
            status=status,
            severity=severity,
            finding_type=finding_type,
            evidence=evidence,
            explanation=explanation,
            remediation=remediation,
            metadata=metadata or {},
        )
