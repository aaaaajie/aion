"""Test-only local flight recorder for the quick Runtime smoke test.

This package deliberately lives under ``scripts``.  It is not part of the
runtime package and is not included by the project's package discovery rules.
"""

from .server import RuntimeMonitor

__all__ = ["RuntimeMonitor"]
