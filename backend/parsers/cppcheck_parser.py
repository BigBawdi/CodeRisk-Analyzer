"""
parsers/cppcheck_parser.py

Provides two things:

1. parse_cppcheck_xml(xml_path) — your original standalone function,
   kept exactly as-is so nothing that already calls it breaks.

2. CppcheckParser — a BaseParser subclass that wraps the function above.
   This is what AnalyzerService (and any future orchestrator) uses.

Why keep the standalone function?
----------------------------------
Your existing tests import parse_cppcheck_xml directly.  Wrapping rather
than replacing means zero breakage.  The class is a thin adapter — all
real logic stays in one place (the function).
"""

import xml.etree.ElementTree as ET
from typing import Any, List

from backend.parsers.base_parser import BaseParser
from backend.normalization.vulnerability_schema import Vulnerability
from backend.normalization.severity_mapper import map_severity
from backend.normalization.type_mapper import map_vulnerability_type


# ---------------------------------------------------------------------------
# Standalone function — original implementation, untouched
# ---------------------------------------------------------------------------

def parse_cppcheck_xml(xml_path: str) -> List[Vulnerability]:
    """
    Parse a Cppcheck XML result file and return a list of Vulnerability objects.

    Parameters
    ----------
    xml_path : str
        Path to the XML file produced by:
            cppcheck --xml --xml-version=2 <target>

    Returns
    -------
    List[Vulnerability]
        One entry per <error> element found in the XML.

    Raises
    ------
    FileNotFoundError : if xml_path does not exist.
    ValueError        : if the file is not valid XML.
    """
    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        raise FileNotFoundError(f"Cppcheck output file not found: {xml_path}")
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML in {xml_path}: {exc}") from exc

    root = tree.getroot()
    issues: List[Vulnerability] = []

    for error in root.findall(".//error"):
        # <location> is a child element in XML v2; fall back to attributes
        # in XML v1 where file/line live directly on <error>.
        location = error.find("location")
        if location is not None:
            file_val = location.get("file")
            line_str = location.get("line")
        else:
            file_val = error.get("file")
            line_str = error.get("line")

        issues.append(
            Vulnerability(
                tool="cppcheck",
                file=file_val,
                line=int(line_str) if line_str and line_str.isdigit() else None,
                vulnerability_type=map_vulnerability_type(error.get("id", "")),
                severity=map_severity(error.get("severity", "")),
                message=error.get("msg", ""),
                cwe=error.get("cwe"),
            )
        )

    return issues


# ---------------------------------------------------------------------------
# Class-based adapter — implements BaseParser
# ---------------------------------------------------------------------------

class CppcheckParser(BaseParser):
    """
    BaseParser implementation for Cppcheck.

    Usage
    -----
        parser = CppcheckParser()
        vulns  = parser.safe_parse("/tmp/cppcheck_output.xml")
        print(parser.summary(vulns))

    What parse() expects
    --------------------
    raw_data : str
        Path to a Cppcheck XML output file (v1 or v2).
    """

    tool_name = "cppcheck"

    def parse(self, raw_data: Any) -> List[Vulnerability]:
        """
        Delegate to parse_cppcheck_xml().

        Parameters
        ----------
        raw_data : str
            File path to the Cppcheck XML output.

        Returns
        -------
        List[Vulnerability]
        """
        if not isinstance(raw_data, str):
            raise ValueError(
                f"CppcheckParser expects a file path (str), "
                f"got {type(raw_data).__name__}."
            )
        return parse_cppcheck_xml(raw_data)