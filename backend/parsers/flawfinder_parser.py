import re
from typing import Any, List, Optional
from pathlib import Path

from backend.parsers.base_parser import BaseParser
from backend.normalization.vulnerability_schema import Vulnerability


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_escape.sub('', text)


# Header pattern.  Column number is optional: filename:line[:col]:  [level] (cat) func:
# Group indices:  1=file  2=line  3=col(optional)  4=level  5=category  6=function
_HEADER_RE = re.compile(
    r'^(.+?):(\d+)(?::(\d+))?:\s+\[(\d+)\]\s+\((\w+)\)\s+([^:]+):$'
)

_CWE_RE = re.compile(r'CWE-(\d+)', re.IGNORECASE)

# Flawfinder 1-5 risk level → normalised severity
_SEVERITY_MAP = {
    5: "CRITICAL",
    4: "HIGH",
    3: "MEDIUM",
    2: "LOW",
    1: "INFO",
}


# ---------------------------------------------------------------------------
# Standalone function — core parsing logic
# ---------------------------------------------------------------------------

def parse_flawfinder_output(output_path: str) -> List[Vulnerability]:
    try:
        with open(output_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Flawfinder output file not found: {output_path}")
    except Exception as exc:
        raise ValueError(f"Failed to read {output_path}: {exc}") from exc
    return _parse_flawfinder_content(content)

def _parse_flawfinder_content(content: str) -> List[Vulnerability]:
    if not content.strip():
        return []

    content = _strip_ansi_codes(content)

    findings: List[Vulnerability] = []
    lines = content.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i].strip()
        match = _HEADER_RE.match(line)

        if match:
            file_path    = match.group(1)
            line_num     = int(match.group(2))
            level        = int(match.group(4))
            category     = match.group(5)
            vuln_func    = match.group(6).strip()

            description_lines: List[str] = []
            i += 1
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line:
                    i += 1
                    continue
                if _HEADER_RE.match(next_line):
                    break
                description_lines.append(next_line)
                i += 1

            description = " ".join(description_lines).strip()
            severity = _SEVERITY_MAP.get(level, "INFO")

            cwe_match = _CWE_RE.search(description)
            cwe = str(cwe_match.group(1)) if cwe_match else None

            full_description = f"{vuln_func}: {description}" if description else vuln_func

            findings.append(
                Vulnerability(
                    tool="flawfinder",
                    file=file_path,
                    line=line_num,
                    vulnerability_type=category,
                    severity=severity,
                    message=full_description,
                    cwe=cwe,
                )
            )
        else:
            i += 1

    return findings


# ---------------------------------------------------------------------------
# Class-based adapter — implements BaseParser
# ---------------------------------------------------------------------------

class FlawfinderParser(BaseParser):
    tool_name = "flawfinder"

    def parse(self, raw_data: Any) -> List[Vulnerability]:
        if not isinstance(raw_data, str):
            raise ValueError(f"FlawfinderParser expects str, got {type(raw_data).__name__}.")
        p = Path(raw_data)
        if p.exists() and p.is_file():
            content = p.read_text(encoding="utf-8", errors="ignore")
        else:
            content = raw_data
        return _parse_flawfinder_content(content)