"""
parsers/coverity_parser.py

Provides two things:

1. parse_coverity_json(json_path) — standalone function that parses
   Coverity's JSON output format. Kept separate so it can be tested
   independently.

2. CoverityParser — a BaseParser subclass that wraps the function above.
   This is what AnalyzerService (and any future orchestrator) uses.

Coverity output format
------------------------
Coverity produces JSON output that typically contains an 'issues' array:

    {
      "issues": [
        {
          "checkerName": "USE_AFTER_FREE",
          "severity": "High",
          "description": "Use after free vulnerability...",
          "strippedFilePath": "/path/to/file.c",
          "mainEventLineNumber": 42,
          "cwe": "CWE-416",
          "impact": "High",
          "category": "Memory Corruption"
        }
      ]
    }

Alternative formats might use 'warnings' or 'defects' as the root key.
"""

import json
import os
from typing import Any, List, Optional, Dict
from pathlib import Path

from backend.parsers.base_parser import BaseParser
from backend.normalization.vulnerability_schema import Vulnerability
from backend.normalization.severity_mapper import map_severity
from backend.normalization.type_mapper import map_vulnerability_type


# ---------------------------------------------------------------------------
# Standalone function — core parsing logic
# ---------------------------------------------------------------------------

def parse_coverity_json(json_path: str) -> List[Vulnerability]:
    """
    Parse a Coverity JSON result file and return a list of Vulnerability objects.

    Parameters
    ----------
    json_path : str
        Path to the JSON file produced by Coverity (e.g., cov-analyze output).

    Returns
    -------
    List[Vulnerability]
        One entry per issue/defect found in the JSON.

    Raises
    ------
    FileNotFoundError : if json_path does not exist.
    ValueError        : if the file is not valid JSON or cannot be read.
    """
    # Check if file exists
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Coverity output file not found: {json_path}")
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {json_path}: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"Failed to read {json_path}: {exc}") from exc

    # Handle different possible root keys in Coverity output
    issues_data = _extract_issues_array(data)
    
    if not issues_data:
        return []  # No issues found
    
    findings: List[Vulnerability] = []
    
    for issue in issues_data:
        # Extract fields with fallbacks for different Coverity output versions
        checker_name = issue.get("checkerName") or issue.get("checker") or ""
        severity_raw = issue.get("severity") or issue.get("impact") or ""
        description = issue.get("description") or issue.get("longDescription") or ""
        file_path = issue.get("strippedFilePath") or issue.get("file") or ""
        
        # Line number can be in different locations
        line_num = _extract_line_number(issue)
        
        # CWE might be direct or in a nested object
        cwe = _extract_cwe(issue)
        
        # Map to standard formats
        vuln_type = map_vulnerability_type(checker_name)
        severity = _map_coverity_severity(severity_raw)
        
        # Build message with additional context if available
        message = description
        if not message and "eventDescription" in issue:
            message = issue.get("eventDescription", "")
        
        # Only add if we have minimum required info
        if file_path or message:
            findings.append(
                Vulnerability(
                    tool="coverity",
                    file=file_path or None,
                    line=line_num,
                    vulnerability_type=vuln_type,
                    severity=severity,
                    message=message or checker_name,
                    cwe=cwe,
                )
            )
    
    return findings


def _extract_issues_array(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract the issues array from Coverity JSON data.
    Handles various possible root keys.
    """
    # Common root keys for Coverity output
    possible_keys = ["issues", "warnings", "defects", "results", "findings"]
    
    for key in possible_keys:
        if key in data and isinstance(data[key], list):
            return data[key]
    
    # If the data itself is an array, return it
    if isinstance(data, list):
        return data
    
    # Check for nested structure: {"result": {"issues": [...]}}
    if "result" in data and isinstance(data["result"], dict):
        for key in possible_keys:
            if key in data["result"] and isinstance(data["result"][key], list):
                return data["result"][key]
    
    return []


def _extract_line_number(issue: Dict[str, Any]) -> Optional[int]:
    """
    Extract line number from various possible Coverity fields.
    """
    # Common line number fields
    line_fields = [
        "mainEventLineNumber",
        "line",
        "lineNumber",
        "firstLineNumber",
        "occurrenceLine",
        "eventLineNumber"
    ]
    
    for field in line_fields:
        if field in issue:
            try:
                return int(issue[field])
            except (ValueError, TypeError):
                pass
    
    # Check nested in mainEvent object
    if "mainEvent" in issue and isinstance(issue["mainEvent"], dict):
        event = issue["mainEvent"]
        for field in ["lineNumber", "line"]:
            if field in event:
                try:
                    return int(event[field])
                except (ValueError, TypeError):
                    pass
    
    # Check events array for first occurrence
    if "events" in issue and isinstance(issue["events"], list) and issue["events"]:
        first_event = issue["events"][0]
        if isinstance(first_event, dict):
            for field in ["lineNumber", "line"]:
                if field in first_event:
                    try:
                        return int(first_event[field])
                    except (ValueError, TypeError):
                        pass
    
    return None


def _extract_cwe(issue: Dict[str, Any]) -> Optional[str]:
    """
    Extract CWE ID from various possible Coverity fields.
    """
    # Direct CWE field
    cwe = issue.get("cwe")
    if cwe:
        cwe_str = str(cwe).strip()
        # Ensure it has CWE- prefix
        if cwe_str.upper().startswith("CWE-"):
            return cwe_str.upper()
        elif cwe_str.isdigit():
            return f"CWE-{cwe_str}"
    
    # Check in metadata or attributes
    if "metadata" in issue and isinstance(issue["metadata"], dict):
        meta = issue["metadata"]
        for key in ["cwe", "CWE", "cweId"]:
            if key in meta:
                cwe_val = str(meta[key])
                if cwe_val.upper().startswith("CWE-"):
                    return cwe_val.upper()
                elif cwe_val.isdigit():
                    return f"CWE-{cwe_val}"
    
    # Check in issue attributes
    if "issueAttributes" in issue and isinstance(issue["issueAttributes"], dict):
        attrs = issue["issueAttributes"]
        if "cwe" in attrs:
            cwe_val = str(attrs["cwe"])
            if cwe_val.upper().startswith("CWE-"):
                return cwe_val.upper()
            elif cwe_val.isdigit():
                return f"CWE-{cwe_val}"
    
    return None


def _map_coverity_severity(severity: str) -> str:
    """
    Map Coverity severity levels to standard severity categories.
    
    Coverity uses various severity scales:
        - High/Medium/Low
        - Critical/Serious/Moderate/Minor
        - 1-5 scale
    """
    if not severity:
        return "Info"
    
    sev_lower = severity.lower().strip()
    
    # Handle string severity levels
    if sev_lower in ["critical", "high", "serious"]:
        return "High"
    elif sev_lower in ["medium", "moderate", "important"]:
        return "Medium"
    elif sev_lower in ["low", "minor", "trivial"]:
        return "Low"
    elif sev_lower in ["info", "note", "style"]:
        return "Info"
    
    # Handle numeric scales
    try:
        level = int(severity)
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
    except (ValueError, TypeError):
        pass
    
    # Default mapping through the standard mapper
    return map_severity(severity)


# ---------------------------------------------------------------------------
# Class-based adapter — implements BaseParser
# ---------------------------------------------------------------------------

class CoverityParser(BaseParser):
    """
    BaseParser implementation for Coverity.

    Usage
    -----
        parser = CoverityParser()
        vulns  = parser.safe_parse("/path/to/coverity_results.json")
        print(parser.summary(vulns))

    What parse() expects
    --------------------
    raw_data : str
        Path to a Coverity JSON output file.
    """

    tool_name = "coverity"

    def parse(self, raw_data: Any) -> List[Vulnerability]:
        """
        Delegate to parse_coverity_json().

        Parameters
        ----------
        raw_data : str
            File path to the Coverity JSON output.

        Returns
        -------
        List[Vulnerability]
        """
        if not isinstance(raw_data, str):
            raise ValueError(
                f"CoverityParser expects a file path (str), "
                f"got {type(raw_data).__name__}."
            )
        
        return parse_coverity_json(raw_data)