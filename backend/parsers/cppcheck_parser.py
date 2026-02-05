# from typing import List
import xml.etree.ElementTree as ET
from backend.normalization.vulnerability_schema import Vulnerability
from backend.normalization.severity_mapper import map_severity
from backend.normalization.type_mapper import map_vulnerability_type


def parse_cppcheck_xml(xml_path):
    """
    Parse a Cppcheck XML result file and return a list of Vulnerability objects.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    issues = []

    for error in root.findall(".//error"):
        issues.append(
            Vulnerability(
                tool="cppcheck",
                file=error.get("file"),
                line=int(error.get("line")) if error.get("line") else None,
                vulnerability_type=map_vulnerability_type(error.get("id")),
                severity=map_severity(error.get("severity")),
                message=error.get("msg"),
                cwe=error.get("cwe")
            )
        )

    return issues   

    


