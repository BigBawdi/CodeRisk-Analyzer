"""
parsers/flawfinder_parser.py

Provides two things:

1. parse_flawfinder_output(output_path) — standalone function that parses
   Flawfinder's text output format. Kept separate so it can be tested
   independently.

2. FlawfinderParser — a BaseParser subclass that wraps the function above.
   This is what AnalyzerService (and any future orchestrator) uses.

Flawfinder output format
------------------------
Flawfinder produces plain text output like:

    /path/to/file.c:42:  [4] (buffer) strcpy:
      Does not check for buffer overflows when copying to destination (CWE-120).
      Consider using strcpy_s, strncpy, or strlcpy (warning, strncpy is easily misused).

    /path/to/other.c:108:  [2] (race) chown:
      Time of check, time of use race condition with chown (CWE-362).

The format is:
    filename:line:  [level] (category) function:
      Description line 1
      Description line 2...

Where:
    - level is 1-5 (1=least risky, 5=most risky)
    - category is in parentheses (e.g., buffer, race, format, etc.)
    - function is the vulnerable function name
"""

import re
from typing import Any, List, Optional, Dict
from pathlib import Path

from backend.parsers.base_parser import BaseParser
from backend.normalization.vulnerability_schema import Vulnerability
from backend.normalization.severity_mapper import map_severity
from backend.normalization.type_mapper import map_vulnerability_type


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape sequences from text.
    
    ANSI escape sequences are used for colors and formatting in terminal output.
    Pattern matches: ESC[ followed by numbers, semicolons, and a letter.
    """
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_escape.sub('', text)


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
            flawfinder --columns --context --dataonly /path/to/code > output.txt

    Returns
    -------
    List[Vulnerability]
        One entry per finding found in the output.

    Raises
    ------
    FileNotFoundError : if output_path does not exist.
    ValueError        : if the file cannot be read or parsed.
    """
    try:
        with open(output_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Flawfinder output file not found: {output_path}")
    except Exception as exc:
        raise ValueError(f"Failed to read {output_path}: {exc}") from exc

    if not content.strip():
        return []  # Empty file, no findings

    # Strip ANSI color codes before parsing
    content = _strip_ansi_codes(content)
    
    findings: List[Vulnerability] = []
    
    # Parse the output line by line
    lines = content.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        # Look for the finding header: filename:line:  [level] (category) function:
        # Example: /path/to/file.c:42:  [4] (buffer) strcpy:
        pattern = r'^(.+?):(\d+):\s+\[(\d+)\]\s+\((\w+)\)\s+([^:]+):$'
        match = re.match(pattern, line)
        
        if match:
            file_path = match.group(1)
            line_num = int(match.group(2))
            level = int(match.group(3))
            category = match.group(4)
            vulnerable_func = match.group(5).strip()
            
            # Collect the description (can span multiple lines)
            description_lines = []
            i += 1
            
            # Read description lines until we hit another finding header or EOF
            while i < len(lines):
                next_line = lines[i].strip()
                # Skip empty lines but continue collecting
                if not next_line:
                    i += 1
                    continue
                # Check if this is a new finding header
                if re.match(pattern, next_line):
                    # Found next finding
                    break
                description_lines.append(next_line)
                i += 1
            
            # Join description lines
            description = " ".join(description_lines).strip()
            
            # Map severity (1-5 scale to High/Medium/Low/Info)
            severity = _map_flawfinder_level_to_severity(level)
            
            # Extract CWE if present in description
            cwe = _extract_cwe(description)
            
            # Map vulnerability type based on category
            vuln_type = map_vulnerability_type(category)
            
            # Build the message
            message = f"{vulnerable_func}: {description}" if description else vulnerable_func
            
            findings.append(
                Vulnerability(
                    tool="flawfinder",
                    file=file_path,
                    line=line_num,
                    vulnerability_type=vuln_type,
                    severity=severity,
                    message=message,
                    cwe=cwe,
                )
            )
        else:
            i += 1
    
    return findings


def _map_flawfinder_level_to_severity(level: int) -> str:
    """
    Map Flawfinder's 1-5 risk level to standard severity categories.
    
    Flawfinder levels:
        5 = Highest risk (critical)
        4 = High risk
        3 = Medium risk
        2 = Low risk
        1 = Very low risk (info)
    """
    if level >= 5:
        return "Critical"
    elif level == 4:
        return "High"
    elif level == 3:
        return "Medium"
    elif level == 2:
        return "Low"
    else:
        return "Info"


def _extract_cwe(text: str) -> Optional[str]:
    """
    Extract CWE ID from text if present.
    Looks for patterns like "CWE-120" or "(CWE-120)".
    Also handles ANSI codes that might be around the CWE.
    """
    if not text:
        return None
    
    # First strip any remaining ANSI codes
    clean_text = _strip_ansi_codes(text)
    
    # Pattern for CWE-XXX where XXX is a number
    pattern = r'CWE-(\d+)'
    match = re.search(pattern, clean_text, re.IGNORECASE)
    
    if match:
        return f"CWE-{match.group(1)}"
    
    return None


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
        print(parser.summary(vulns))

    What parse() expects
    --------------------
    raw_data : str
        Path to a Flawfinder text output file.
    """

    tool_name = "flawfinder"

    def parse(self, raw_data: Any) -> List[Vulnerability]:
        """
        Delegate to parse_flawfinder_output().

        Parameters
        ----------
        raw_data : str
            File path to the Flawfinder text output.

        Returns
        -------
        List[Vulnerability]
        """
        if not isinstance(raw_data, str):
            raise ValueError(
                f"FlawfinderParser expects a file path (str), "
                f"got {type(raw_data).__name__}."
            )
        
        # Verify the file exists before parsing
        if not Path(raw_data).exists():
            raise FileNotFoundError(f"Flawfinder output file not found: {raw_data}")
        
        return parse_flawfinder_output(raw_data)