"""MaskGuard: AI-powered PII discovery and query-time, role-based masking."""

from importlib.metadata import PackageNotFoundError, version

try:  # the single source of truth is pyproject.toml
    __version__ = version("maskguard")
except PackageNotFoundError:  # imported from a source tree that was never installed
    __version__ = "0+unknown"
