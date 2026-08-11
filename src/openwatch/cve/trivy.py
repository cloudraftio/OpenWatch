"""Trivy/Grype (container image) source - STUB."""
from __future__ import annotations

from .base import CVEFinding, CVESource

TRIVY_COMMAND_TEMPLATE = "trivy image --format json {image_ref}"  # No API key needed, just the binary.


class TrivySource(CVESource):
    """NOT IMPLEMENTED: would run trivy image --format json against the container image."""

    name = "trivy"

    def __init__(self, image_ref: str):
        self.image_ref = image_ref

    def collect(self) -> list[CVEFinding]:
        raise NotImplementedError(
            f"TrivySource is a stub - would run `{TRIVY_COMMAND_TEMPLATE.format(image_ref=self.image_ref)}`."
        )
