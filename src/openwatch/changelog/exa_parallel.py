"""Exa/Parallel changelog enrichment - STUB; not used for stage 2, only for content beyond the release body."""
from __future__ import annotations

from .base import ChangelogParser, ChangelogSummary

DEFAULT_PROMPT = (
    "Summarise this release's changelog into: 1) user-facing "
    "highlights, 2) security-relevant fixes (call out CVE ids if present)."
)


class ExaOrParallelChangelogParser(ChangelogParser):
    """NOT IMPLEMENTED: would call Exa's /answer or Parallel's Task API with DEFAULT_PROMPT."""

    def __init__(self, api_key: str, provider: str = "exa"):
        self.api_key = api_key
        self.provider = provider

    def parse(self, tag: str, raw_body: str) -> ChangelogSummary:
        raise NotImplementedError(f"ExaOrParallelChangelogParser ({self.provider}) is a stub.")
