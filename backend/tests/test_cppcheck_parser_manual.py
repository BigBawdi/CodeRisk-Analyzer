from backend.parsers.cppcheck_parser import parse_cppcheck_xml
from backend.normalization.vulnerability_schema import Vulnerability



def test_cppcheck_parser_parses_vulnerabilities():
    with open("backend/data/sample_results/cppcheck_sample.xml", "r", encoding="utf-8") as f:
        raw_data = f.read()
        xml_path = "backend/data/sample_results/cppcheck_sample.xml"

    vulnerabilities = parse_cppcheck_xml(xml_path)

    assert len(vulnerabilities) > 0


def test_cppcheck_parser_fields_are_populated():
    with open("backend/data/sample_results/cppcheck_sample.xml", "r", encoding="utf-8") as f:
        raw_data = f.read()
        xml_path = "backend/data/sample_results/cppcheck_sample.xml"

    vulnerabilities = parse_cppcheck_xml(xml_path)

    vuln = vulnerabilities[0]

    assert vuln.tool == "cppcheck"
    assert vuln.file is not None
    assert vuln.line is not None
    assert vuln.severity in {"Low", "Medium", "High"}

