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
    tool_name = "cppcheck"

    def parse(self, raw_data: Any) -> List[Vulnerability]:
        if not isinstance(raw_data, str):
            raise ValueError(
                f"CppcheckParser expects a file path (str), "
                f"got {type(raw_data).__name__}."
            )
        return parse_cppcheck_xml(raw_data)