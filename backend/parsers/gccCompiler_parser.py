from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from backend.normalization.vulnerability_schema import Vulnerability

logger = logging.getLogger(__name__)


class GCCAnalyzerParser:
    """
    Parse GCC -fanalyzer JSON diagnostics into Vulnerability objects.

    AnalysisService calls  safe_parse(path)  where *path* is a temp file
    containing the merged JSON array written from proc.stderr.
    """

    TOOL_ID = "gcc_analyzer"

    # Map GCC diagnostic "kind" → normalised severity label
    _SEVERITY_MAP = {
        "warning": "WARNING",
        "error":   "ERROR",
        "note":    "INFO",     # notes are context; filtered out below
    }

    def safe_parse(self, path_or_text: str) -> List[Vulnerability]:
        """
        Parse GCC JSON diagnostics.  Never raises — returns [] on any error.

        Parameters
        ----------
        path_or_text:
            Either a file path (written by AnalysisService) containing the
            JSON array, or the raw JSON string itself.
        """
        try:
            return self._parse(path_or_text)
        except Exception as exc:
            logger.exception("[%s] Unexpected parse error: %s", self.TOOL_ID, exc)
            return []

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _parse(self, path_or_text: str) -> List[Vulnerability]:
        raw = self._load(path_or_text)
        if not raw or not raw.strip():
            logger.info("[%s] Empty input — no findings.", self.TOOL_ID)
            return []

        diagnostics = self._load_json(raw)
        if not diagnostics:
            return []

        findings: List[Vulnerability] = []
        for diag in diagnostics:
            vuln = self._diag_to_vulnerability(diag)
            if vuln is not None:
                findings.append(vuln)

        logger.info("[%s] Parsed %d finding(s).", self.TOOL_ID, len(findings))
        return findings

    def _load(self, path_or_text: str) -> str:
        """Read from a file path, or return the string directly."""
        p = Path(path_or_text)
        if p.exists() and p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.warning("[%s] Could not read file %s: %s", self.TOOL_ID, p, exc)
                return ""
        # Treat as raw text (e.g. when called directly in tests)
        return path_or_text

    def _load_json(self, raw: str) -> list:
        """
        Parse the JSON array from *raw*.

        GCC may prepend a plain-text "In function …" header before the JSON
        array when there are hard compilation errors.  Slice to the array.
        """
        start = raw.find("[")
        end   = raw.rfind("]")
        if start == -1 or end == -1 or end < start:
            # Could be an empty file ("[]" written when no source files found)
            stripped = raw.strip()
            if stripped in ("", "[]"):
                return []
            logger.warning(
                "[%s] No JSON array found in input. First 300 chars:\n%s",
                self.TOOL_ID, raw[:300],
            )
            return []

        try:
            return json.loads(raw[start : end + 1])
        except json.JSONDecodeError as exc:
            logger.warning("[%s] JSON decode error: %s", self.TOOL_ID, exc)
            return []

    def _diag_to_vulnerability(self, diag: dict) -> Optional[Vulnerability]:
        """Convert one GCC JSON diagnostic dict to a Vulnerability, or None to skip."""
        kind = diag.get("kind", "warning")

        # Skip 'note' entries — they are context annotations attached to a
        # parent warning, not independent findings.
        if kind == "note":
            return None

        severity = self._SEVERITY_MAP.get(kind, "WARNING")
        message  = diag.get("message", "")
        option   = diag.get("option", "")

        # Primary caret location
        file_path, line_no, col_no = "unknown", 0, 0
        locations = diag.get("locations", [])
        if locations:
            caret     = locations[0].get("caret", {})
            file_path = caret.get("file", "unknown")
            line_no   = caret.get("line", 0)
            col_no    = caret.get("column", 0)

        # CWE number (present for -fanalyzer findings, absent for plain -Wall warnings)
        cwe_raw = diag.get("metadata", {}).get("cwe")
        cwe     = int(cwe_raw) if cwe_raw is not None else None

        # Build a human-readable description that includes the flag name
        description = message
        if option:
            description = f"{message}  [{option}]"

        return Vulnerability(
            tool=self.TOOL_ID,
            severity=severity,
            file=file_path,
            line=line_no,
            column=col_no,
            description=description,
            cwe=cwe,
        )
