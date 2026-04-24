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
    """
    Parse a Flawfinder text output file and return a list of Vulnerability objects.

    Parameters
    ----------
    output_path : str
        Path to the text file produced by:
            flawfinder --columns --dataonly --quiet /path/to/code

    Returns
    -------
    List[Vulnerability]
        One entry per finding found in the output.

    Raises
    ------
    FileNotFoundError : if output_path does not exist.
    ValueError        : if the file cannot be read.
    """
    try:
        with open(output_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Flawfinder output file not found: {output_path}")
    except Exception as exc:
        raise ValueError(f"Failed to read {output_path}: {exc}") from exc

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
            col_num      = int(match.group(3)) if match.group(3) else 0
            level        = int(match.group(4))
            category     = match.group(5)           # e.g. "buffer", "race"
            vuln_func    = match.group(6).strip()   # e.g. "strcpy"

            # Collect description — may span multiple lines.
            # Inner loop leaves i pointing at the next header (or past EOF)
            # so the outer loop will re-evaluate it correctly without skipping.
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
            cwe = int(cwe_match.group(1)) if cwe_match else None

            # Prepend the vulnerable function name so the description is self-contained
            full_description = f"{vuln_func}: {description}" if description else vuln_func

            findings.append(
                Vulnerability(
                    tool="flawfinder",
                    file=file_path,
                    line=line_num,
                    column=col_num,
                    severity=severity,
                    description=full_description,   # FIX: was 'message='; wrong field name
                    cwe=cwe,
                    # FIX: 'vulnerability_type=vuln_type' removed — not a Vulnerability field
                )
            )
        else:
            i += 1

    return findings


# ---------------------------------------------------------------------------
# Class-based adapter — implements BaseParser
# ---------------------------------------------------------------------------

class FlawfinderParser(BaseParser):
    """
    BaseParser implementation for Flawfinder.

    Usage
    -----
        parser = FlawfinderParser()
        vulns  = parser.safe_parse("/tmp/flawfinder_output.txt")

    What parse() expects
    --------------------
    raw_data : str
        Path to a Flawfinder text output file written by AnalysisService.
    """

    tool_name = "flawfinder"

    def parse(self, raw_data: Any) -> List[Vulnerability]:
        if not isinstance(raw_data, str):
            raise ValueError(
                f"FlawfinderParser expects a file path (str), "
                f"got {type(raw_data).__name__}."
            )
        if not Path(raw_data).exists():
            raise FileNotFoundError(f"Flawfinder output file not found: {raw_data}")

        return parse_flawfinder_output(raw_data)