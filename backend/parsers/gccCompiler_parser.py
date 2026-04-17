"""
parsers/gcc_analyzer_parser.py
"""

import re
import os
from typing import Any, List, Optional

from backend.parsers.base_parser import BaseParser
from backend.normalization.vulnerability_schema import Vulnerability
from backend.normalization.severity_mapper import map_severity
from backend.normalization.type_mapper import map_vulnerability_type


def parse_gcc_analyzer_output(raw_output: str) -> List[Vulnerability]:
    # Determine if raw_output is a file path or direct string content
    if os.path.exists(raw_output):
        with open(raw_output, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    else:
        content = raw_output

    if not content.strip():
        return []

    findings = []
    seen = set()

    # Match lines like:
    #   file.c:42:5: warning: message text [CWE-123] [-Wanalyzer-foo]
    #   file.c:42:5: warning: message text [-Wanalyzer-foo]
    # The analyzer flag [-Wanalyzer-...] is always the LAST bracket group.
    # Everything before it (including optional [CWE-xxx]) is part of the message.
    pattern = re.compile(
        r'^(.+?):(\d+)(?::\d+)?:\s+(warning|error|note):\s+(.*?)\s+(\[-Wanalyzer-[^\]]+\])\s*$',
        re.MULTILINE
    )

    for match in pattern.finditer(content):
        file_path = match.group(1)
        line_str = match.group(2)
        severity_str = match.group(3)
        message = match.group(4).strip()
        flags = match.group(5).strip()  # e.g. [-Wanalyzer-null-dereference]

        # Deduplicate
        key = f"{file_path}:{line_str}:{message[:40]}"
        if key in seen:
            continue
        seen.add(key)

        # Extract CWE from message (e.g., [CWE-476])
        cwe_match = re.search(r'\[CWE-(\d+)\]', message, re.IGNORECASE)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else None

        # Strip the [CWE-xxx] tag from message for cleanliness
        clean_message = re.sub(r'\s*\[CWE-\d+\]', '', message).strip()

        # Extract analyzer type from flags (e.g., -Wanalyzer-null-dereference)
        type_match = re.search(r'-Wanalyzer-([a-zA-Z0-9_-]+)', flags)
        analyzer_type = type_match.group(1) if type_match else ""

        # Severity mapping
        sev = severity_str.lower()
        if sev == "error":
            severity = "High"
        elif sev == "note":
            severity = "Info"
        else:  # warning
            high_types = ["null-dereference", "use-after-free", "double-free", "buffer-overflow"]
            severity = "High" if any(t in analyzer_type for t in high_types) else "Medium"

        vuln_type = map_vulnerability_type(analyzer_type)

        findings.append(
            Vulnerability(
                tool="gcc_analyzer",
                file=file_path,
                line=int(line_str),
                vulnerability_type=vuln_type,
                severity=severity,
                message=clean_message,
                cwe=cwe,
            )
        )

    return findings


class GCCAnalyzerParser(BaseParser):
    tool_name = "gcc_analyzer"

    def parse(self, raw_data: Any) -> List[Vulnerability]:
        if not isinstance(raw_data, str):
            raise ValueError(f"GCCAnalyzerParser expects a string, got {type(raw_data).__name__}")
        return parse_gcc_analyzer_output(raw_data)