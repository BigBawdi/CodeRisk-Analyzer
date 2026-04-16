"""
tests/test_parsers.py

Tests for BaseParser (via a minimal concrete subclass) and CppcheckParser.

Run with:
    python -m pytest backend/tests/test_parsers.py -v
"""

import os
import textwrap
import tempfile
import pytest

from backend.parsers.base_parser import BaseParser
from backend.parsers.cppcheck_parser import CppcheckParser, parse_cppcheck_xml
from backend.normalization.vulnerability_schema import Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_xml(content: str) -> str:
    """Write XML string to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


VALID_CPPCHECK_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <results version="2">
      <cppcheck version="2.9"/>
      <errors>
        <error id="nullPointer" severity="error" msg="Null pointer dereference" cwe="476">
          <location file="src/main.c" line="42"/>
        </error>
        <error id="memoryLeak" severity="warning" msg="Memory leak: buf" cwe="401">
          <location file="src/utils.c" line="17"/>
        </error>
        <error id="variableScope" severity="style" msg="Variable scope can be reduced">
          <location file="src/helper.c" line="5"/>
        </error>
      </errors>
    </results>
""")


# ---------------------------------------------------------------------------
# Minimal concrete subclass — lets us test BaseParser behaviour directly
# ---------------------------------------------------------------------------

class _EchoParser(BaseParser):
    """Returns whatever list you hand to its constructor — for testing only."""

    tool_name = "echo"

    def __init__(self, findings=None):
        self._findings = findings or []

    def parse(self, raw_data):
        return self._findings


class _BrokenParser(BaseParser):
    """Always raises — lets us test safe_parse error handling."""

    tool_name = "broken"

    def parse(self, raw_data):
        raise RuntimeError("simulated failure")


# ===========================================================================
# BaseParser tests
# ===========================================================================

class TestBaseParser:

    def test_repr_shows_tool_name(self):
        p = _EchoParser()
        assert "echo" in repr(p)

    def test_safe_parse_returns_findings_on_success(self):
        vuln = Vulnerability(tool="echo", file="f.c", line=1,
                             vulnerability_type="Other", severity="High",
                             message="test msg")
        p = _EchoParser(findings=[vuln])
        result = p.safe_parse("anything")
        assert len(result) == 1

    def test_safe_parse_returns_empty_list_on_exception(self):
        p = _BrokenParser()
        result = p.safe_parse("anything")
        assert result == []

    def test_validate_drops_finding_with_empty_message(self):
        bad = Vulnerability(tool="echo", file="f.c", line=1,
                            vulnerability_type="Other", severity="High",
                            message="")          # empty message
        good = Vulnerability(tool="echo", file="f.c", line=2,
                             vulnerability_type="Other", severity="Low",
                             message="real msg")
        p = _EchoParser(findings=[bad, good])
        result = p.safe_parse("x")
        assert len(result) == 1
        assert result[0].message == "real msg"

    def test_validate_drops_finding_with_missing_severity(self):
        bad = Vulnerability(tool="echo", file="f.c", line=1,
                            vulnerability_type="Other", severity="",
                            message="msg")
        p = _EchoParser(findings=[bad])
        result = p.safe_parse("x")
        assert result == []

    def test_summary_counts_by_severity(self):
        findings = [
            Vulnerability(tool="t", file="f", line=1, vulnerability_type="Other",
                          severity="High", message="a"),
            Vulnerability(tool="t", file="f", line=2, vulnerability_type="Other",
                          severity="High", message="b"),
            Vulnerability(tool="t", file="f", line=3, vulnerability_type="Other",
                          severity="Low",  message="c"),
        ]
        p = _EchoParser()
        counts = p.summary(findings)
        assert counts == {"High": 2, "Low": 1}

    def test_summary_empty_input(self):
        p = _EchoParser()
        assert p.summary([]) == {}

    def test_cannot_instantiate_base_directly(self):
        with pytest.raises(TypeError):
            BaseParser()


# ===========================================================================
# CppcheckParser tests
# ===========================================================================

class TestCppcheckParser:

    def test_tool_name_is_cppcheck(self):
        assert CppcheckParser.tool_name == "cppcheck"

    def test_is_subclass_of_base_parser(self):
        assert issubclass(CppcheckParser, BaseParser)

    def test_parse_returns_correct_count(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 3

    def test_severity_mapping_error_to_high(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        null_ptr = next(v for v in vulns if "Null" in v.vulnerability_type)
        assert null_ptr.severity == "High"

    def test_severity_mapping_warning_to_medium(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        mem_leak = next(v for v in vulns if "Memory" in v.vulnerability_type)
        assert mem_leak.severity == "Medium"

    def test_severity_mapping_style_to_low(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        style = next(v for v in vulns if v.message == "Variable scope can be reduced")
        assert style.severity == "Low"

    def test_type_mapping_null_pointer(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        null_ptr = next(v for v in vulns if "Null" in v.vulnerability_type)
        assert null_ptr.vulnerability_type == "Null Pointer Dereference"

    def test_type_mapping_memory_leak(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        mem = next(v for v in vulns if "Memory" in v.vulnerability_type)
        assert mem.vulnerability_type == "Memory Management"

    def test_cwe_is_preserved(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        null_ptr = next(v for v in vulns if "Null" in v.vulnerability_type)
        assert null_ptr.cwe == "476"

    def test_line_number_is_int(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        assert all(isinstance(v.line, int) for v in vulns)

    def test_tool_field_is_cppcheck(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        assert all(v.tool == "cppcheck" for v in vulns)

    def test_safe_parse_on_missing_file(self):
        parser = CppcheckParser()
        result = parser.safe_parse("/nonexistent/path/output.xml")
        assert result == []

    def test_safe_parse_on_bad_xml(self):
        path = _write_xml("<broken xml <<< not valid")
        try:
            result = CppcheckParser().safe_parse(path)
        finally:
            os.unlink(path)
        assert result == []

    def test_raises_value_error_on_non_string_input(self):
        with pytest.raises(ValueError):
            CppcheckParser().parse(12345)

    def test_empty_errors_block_returns_empty_list(self):
        xml = '<?xml version="1.0"?><results version="2"><errors></errors></results>'
        path = _write_xml(xml)
        try:
            vulns = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        assert vulns == []

    def test_standalone_function_returns_same_as_class(self):
        path = _write_xml(VALID_CPPCHECK_XML)
        try:
            from_fn    = parse_cppcheck_xml(path)
            from_class = CppcheckParser().parse(path)
        finally:
            os.unlink(path)
        assert len(from_fn) == len(from_class)
        for a, b in zip(from_fn, from_class):
            assert a.message == b.message
            assert a.severity == b.severity