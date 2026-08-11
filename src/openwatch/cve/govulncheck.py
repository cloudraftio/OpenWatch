"""govulncheck (Go module dependency) source - STUB."""
from __future__ import annotations

from .base import CVEFinding, CVESource

GOVULNCHECK_COMMAND = "govulncheck -json ./..."  # No API key needed, just the binary.


class GovulncheckSource(CVESource):
    """NOT IMPLEMENTED: would run govulncheck -json against a checked-out module."""

    name = "govulncheck"

    def __init__(self, module_path: str):
        self.module_path = module_path

    def collect(self) -> list[CVEFinding]:
        raise NotImplementedError(f"GovulncheckSource is a stub - would run `{GOVULNCHECK_COMMAND}`.")
