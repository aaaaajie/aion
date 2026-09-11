"""Read-only static compatibility auditing for YAML POC collections."""

from .audit import AuditLimits, SourceConfig, audit_sources

__all__ = ["AuditLimits", "SourceConfig", "audit_sources"]
