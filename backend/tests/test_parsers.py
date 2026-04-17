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
from backend.parsers.flawfinder_parser import FlawfinderParser, parse_flawfinder_output
from backend.parsers.coverity_parser import CoverityParser, parse_coverity_json
from backend.parsers.gccCompiler_parser import GCCAnalyzerParser, parse_gcc_analyzer_output
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

def _write_coverity_json(content: str) -> str:
    """Write Coverity JSON string to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def _write_gcc_output(content: str) -> str:
    """Write GCC output string to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path

VALID_COVERITY_JSON = """{
  "issues": [
    {
      "checkerName": "USE_AFTER_FREE",
      "severity": "High",
      "description": "Using 'ptr' after it has been freed",
      "strippedFilePath": "/home/user/project/src/main.c",
      "mainEventLineNumber": 42,
      "cwe": "CWE-416",
      "impact": "High",
      "category": "Memory Corruption"
    },
    {
      "checkerName": "NULL_RETURNS",
      "severity": "Medium",
      "description": "Possible NULL pointer dereference from malloc return",
      "strippedFilePath": "/home/user/project/src/utils.c",
      "mainEventLineNumber": 108,
      "cwe": "CWE-476"
    },
    {
      "checkerName": "RESOURCE_LEAK",
      "severity": "Low",
      "description": "File descriptor 'fd' not closed before function exit",
      "strippedFilePath": "/home/user/project/src/io.c",
      "mainEventLineNumber": 23,
      "cwe": "CWE-404"
    },
    {
      "checkerName": "UNINIT",
      "severity": "Info",
      "description": "Variable 'ret' may be used uninitialized",
      "strippedFilePath": "/home/user/project/src/helper.c",
      "mainEventLineNumber": 67
    }
  ]
}"""

VALID_COVERITY_JSON_ALTERNATE = """{
  "warnings": [
    {
      "checker": "BUFFER_OVERFLOW",
      "severity": "Critical",
      "longDescription": "Buffer overflow in strcpy call",
      "file": "/home/user/project/src/buffer.c",
      "line": 156,
      "cwe": "CWE-120"
    }
  ]
}"""

VALID_GCC_OUTPUT = """/home/user/project/src/main.c: In function 'main':
/home/user/project/src/main.c:42:5: warning: use of NULL where non-null expected [CWE-476] [-Wanalyzer-null-dereference]
   42 |     *ptr = 42;
      |     ^~~~
/home/user/project/src/utils.c: In function 'process_file':
/home/user/project/src/utils.c:108:10: warning: leak of FILE 'fp' [CWE-404] [-Wanalyzer-file-leak]
  108 |     return;
      |          ^
/home/user/project/src/memory.c:23:5: warning: use after free of 'data' [-Wanalyzer-use-after-free]
   23 |     data[0] = 'x';
      |     ^~~~
/home/user/project/src/format.c:67:3: warning: format string is not a string literal [-Wanalyzer-format-string]
   67 |   printf(user_input);
      |   ^~~~~~~~~~~~~~~~~~
/home/user/project/src/uninit.c:15:8: warning: 'result' may be used uninitialized [-Wanalyzer-uninitialized]
   15 |   return result;
      |          ^~~~~~
"""

VALID_GCC_OUTPUT_SHORT = """/home/user/project/src/main.c:42:5: warning: use of NULL where non-null expected [-Wanalyzer-null-dereference]
/home/user/project/src/memory.c:23:5: warning: use after free of 'data' [-Wanalyzer-use-after-free]
/home/user/project/src/format.c:67:3: warning: format string is not a string literal [-Wanalyzer-format-string]
"""

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

def _write_flawfinder_output(content: str) -> str:
    """Write Flawfinder output string to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


# Add this constant with sample Flawfinder output
VALID_FLAWFINDER_OUTPUT = textwrap.dedent("""\
    /home/user/project/src/main.c:42:  [4] (buffer) strcpy:
      Does not check for buffer overflows when copying to destination (CWE-120).
      Consider using strcpy_s, strncpy, or strlcpy (warning, strncpy is easily misused).

    /home/user/project/src/utils.c:108:  [2] (race) chown:
      Time of check, time of use race condition with chown (CWE-362).
      This can lead to privilege escalation if an attacker can replace the file
      between the check and use.

    /home/user/project/src/network.c:23:  [5] (shell) system:
      Passing user-controlled input to system() can lead to command injection (CWE-78).

    /home/user/project/src/format.c:67:  [3] (format) printf:
      Format string vulnerability - user-controlled format string (CWE-134).

    /home/user/project/src/memory.c:89:  [1] (misc) getenv:
      Environment variable could be manipulated by attacker (CWE-807).
""")


# ===========================================================================
# FlawfinderParser tests
# ===========================================================================

class TestFlawfinderParser:

    def test_tool_name_is_flawfinder(self):
        assert FlawfinderParser.tool_name == "flawfinder"

    def test_is_subclass_of_base_parser(self):
        assert issubclass(FlawfinderParser, BaseParser)

    def test_parse_returns_correct_count(self):
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 5

    def test_severity_mapping_level_5_to_critical(self):
        """Level 5 (highest risk) should map to Critical"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        system_vuln = next(v for v in vulns if "system" in v.message.lower())
        assert system_vuln.severity == "Critical"

    def test_severity_mapping_level_4_to_high(self):
        """Level 4 should map to High"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        strcpy_vuln = next(v for v in vulns if "strcpy" in v.message.lower())
        assert strcpy_vuln.severity == "High"

    def test_severity_mapping_level_3_to_medium(self):
        """Level 3 should map to Medium"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        printf_vuln = next(v for v in vulns if "printf" in v.message.lower())
        assert printf_vuln.severity == "Medium"

    def test_severity_mapping_level_2_to_low(self):
        """Level 2 should map to Low"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        chown_vuln = next(v for v in vulns if "chown" in v.message.lower())
        assert chown_vuln.severity == "Low"

    def test_severity_mapping_level_1_to_info(self):
        """Level 1 (lowest risk) should map to Info"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        getenv_vuln = next(v for v in vulns if "getenv" in v.message.lower())
        assert getenv_vuln.severity == "Info"

    def test_file_path_extraction(self):
        """Should correctly extract file path from output"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        strcpy_vuln = next(v for v in vulns if "strcpy" in v.message.lower())
        assert strcpy_vuln.file == "/home/user/project/src/main.c"

    def test_line_number_extraction(self):
        """Should correctly extract and convert line numbers to int"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        strcpy_vuln = next(v for v in vulns if "strcpy" in v.message.lower())
        assert strcpy_vuln.line == 42
        assert isinstance(strcpy_vuln.line, int)

    def test_cwe_extraction(self):
        """Should extract CWE ID from description text"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        strcpy_vuln = next(v for v in vulns if "strcpy" in v.message.lower())
        assert strcpy_vuln.cwe == "CWE-120"
        
        system_vuln = next(v for v in vulns if "system" in v.message.lower())
        assert system_vuln.cwe == "CWE-78"

    def test_message_includes_vulnerable_function_and_description(self):
        """Message should contain both function name and description"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        strcpy_vuln = next(v for v in vulns if "strcpy" in v.message.lower())
        assert "strcpy:" in strcpy_vuln.message
        assert "buffer overflows" in strcpy_vuln.message

    def test_multiline_description_handling(self):
        """Should properly handle descriptions that span multiple lines"""
        multiline_output = textwrap.dedent("""\
            /test/file.c:10:  [4] (buffer) strcpy:
              First line of description.
              Second line of description.
              Third line with CWE-120.
        """)
        path = _write_flawfinder_output(multiline_output)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 1
        vuln = vulns[0]
        assert "First line" in vuln.message
        assert "Second line" in vuln.message
        assert "Third line" in vuln.message

    def test_vulnerability_type_mapping(self):
        """Should map Flawfinder categories to standard vulnerability types"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        
        # Check that each finding has a non-empty vulnerability_type
        for vuln in vulns:
            assert vuln.vulnerability_type
            assert vuln.vulnerability_type != ""

    def test_tool_field_is_flawfinder(self):
        """All vulnerabilities should have tool='flawfinder'"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        assert all(v.tool == "flawfinder" for v in vulns)

    def test_empty_file_returns_empty_list(self):
        """Parser should return empty list for empty output file"""
        path = _write_flawfinder_output("")
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        assert vulns == []

    def test_file_with_no_findings_returns_empty_list(self):
        """Parser should handle output with no vulnerabilities gracefully"""
        no_findings_output = textwrap.dedent("""\
            Flawfinder version 2.0.19, (C) 2001-2019 David A. Wheeler.
            Number of rules (primarily dangerous function names) in C/C++ ruleset: 223
            Examining test.c
            Examining test.c...

            Not scanning test.c for C++ code.

            No hits found.
        """)
        path = _write_flawfinder_output(no_findings_output)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        assert vulns == []

    def test_safe_parse_on_missing_file(self):
        """safe_parse should return empty list when file is missing"""
        parser = FlawfinderParser()
        result = parser.safe_parse("/nonexistent/path/flawfinder.txt")
        assert result == []

    def test_safe_parse_on_unreadable_file(self):
        """safe_parse should handle file read errors gracefully"""
        parser = FlawfinderParser()
        # Use a directory path - can't be read as a file
        result = parser.safe_parse("/")
        assert result == []

    def test_raises_value_error_on_non_string_input(self):
        """parse should raise ValueError if not given a string path"""
        with pytest.raises(ValueError, match="expects a file path"):
            FlawfinderParser().parse(12345)
        
        with pytest.raises(ValueError, match="expects a file path"):
            FlawfinderParser().parse(["not", "a", "string"])

    def test_raises_file_not_found_on_nonexistent_path(self):
        """parse should raise FileNotFoundError for nonexistent files"""
        with pytest.raises(FileNotFoundError):
            FlawfinderParser().parse("/definitely/does/not/exist/output.txt")

    def test_handles_varying_whitespace_in_output(self):
        """Should handle different amounts of whitespace between fields"""
        varied_whitespace = textwrap.dedent("""\
            /test/file.c:10:     [4]     (buffer)    strcpy:
              Description here.
            
            /test/file2.c:20:\t[2]\t(race)\tchown:
              Another description.
        """)
        path = _write_flawfinder_output(varied_whitespace)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 2
        assert vulns[0].file == "/test/file.c"
        assert vulns[1].file == "/test/file2.c"

    def test_handles_absolute_and_relative_paths(self):
        """Should work with both absolute and relative file paths"""
        mixed_paths = textwrap.dedent("""\
            /absolute/path/file.c:10:  [4] (buffer) strcpy:
              Absolute path test.
            
            ./relative/path/file.c:20:  [3] (format) printf:
              Relative path test.
            
            ../parent/dir/file.c:30:  [2] (race) chown:
              Parent relative test.
        """)
        path = _write_flawfinder_output(mixed_paths)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 3
        assert vulns[0].file == "/absolute/path/file.c"
        assert vulns[1].file == "./relative/path/file.c"
        assert vulns[2].file == "../parent/dir/file.c"

    def test_standalone_function_returns_same_as_class(self):
        """The standalone function should produce identical results to the class method"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            from_fn = parse_flawfinder_output(path)
            from_class = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        
        assert len(from_fn) == len(from_class)
        for a, b in zip(from_fn, from_class):
            assert a.file == b.file
            assert a.line == b.line
            assert a.severity == b.severity
            assert a.message == b.message
            assert a.cwe == b.cwe
            assert a.vulnerability_type == b.vulnerability_type

    def test_handles_output_with_ansi_color_codes(self):
        """Should handle output that contains ANSI color escape sequences"""
        # Use actual escape character \x1b for ANSI codes
        colored_output = (
            "\x1b[1;34m/test/file.c:42:\x1b[0m  \x1b[1;31m[4]\x1b[0m (buffer) strcpy:\n"
            "  Description with \x1b[1mCWE-120\x1b[0m.\n"
        )
        path = _write_flawfinder_output(colored_output)
        try:
            vulns = FlawfinderParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 1
        vuln = vulns[0]
        assert vuln.line == 42
        assert vuln.cwe == "CWE-120"
        assert vuln.file == "/test/file.c"
        assert "strcpy" in vuln.message

    def test_integration_with_base_parser_validate(self):
        """Should work correctly with BaseParser's validation methods"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            parser = FlawfinderParser()
            vulns = parser.parse(path)
            validated = parser.validate(vulns)
        finally:
            os.unlink(path)
        
        # All our test vulnerabilities should be valid
        assert len(validated) == 5

    def test_integration_with_base_parser_summary(self):
        """Summary should correctly count vulnerabilities by severity"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            parser = FlawfinderParser()
            vulns = parser.parse(path)
            summary = parser.summary(vulns)
        finally:
            os.unlink(path)
        
        assert summary == {
            "Critical": 1,  # system (level 5)
            "High": 1,      # strcpy (level 4)
            "Medium": 1,    # printf (level 3)
            "Low": 1,       # chown (level 2)
            "Info": 1,      # getenv (level 1)
        }

    def test_integration_with_safe_parse(self):
        """safe_parse should return validated vulnerabilities"""
        path = _write_flawfinder_output(VALID_FLAWFINDER_OUTPUT)
        try:
            parser = FlawfinderParser()
            vulns = parser.safe_parse(path)
        finally:
            os.unlink(path)
        
        assert len(vulns) == 5
        # All returned vulnerabilities should have required fields
        for vuln in vulns:
            assert vuln.tool == "flawfinder"
            assert vuln.severity
            assert vuln.message

    def test_repr_shows_correct_information(self):
        """__repr__ should show class name and tool name"""
        parser = FlawfinderParser()
        repr_str = repr(parser)
        assert "FlawfinderParser" in repr_str
        assert "flawfinder" in repr_str

# ===========================================================================
# CoverityParser tests
# ===========================================================================

class TestCoverityParser:

    def test_tool_name_is_coverity(self):
        assert CoverityParser.tool_name == "coverity"

    def test_is_subclass_of_base_parser(self):
        assert issubclass(CoverityParser, BaseParser)

    def test_parse_returns_correct_count(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 4

    def test_severity_mapping_high(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        use_after_free = next(v for v in vulns if "USE_AFTER_FREE" in v.vulnerability_type or "after it has been freed" in v.message)
        assert use_after_free.severity == "High"

    def test_severity_mapping_medium(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        null_returns = next(v for v in vulns if "NULL" in v.message or "NULL_RETURNS" in v.vulnerability_type)
        assert null_returns.severity == "Medium"

    def test_severity_mapping_low(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        resource_leak = next(v for v in vulns if "RESOURCE_LEAK" in v.vulnerability_type or "not closed" in v.message)
        assert resource_leak.severity == "Low"

    def test_severity_mapping_info(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        uninit = next(v for v in vulns if "UNINIT" in v.vulnerability_type or "uninitialized" in v.message.lower())
        assert uninit.severity == "Info"

    def test_file_path_extraction(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        use_after_free = next(v for v in vulns if "after it has been freed" in v.message)
        assert use_after_free.file == "/home/user/project/src/main.c"

    def test_line_number_extraction(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        use_after_free = next(v for v in vulns if "after it has been freed" in v.message)
        assert use_after_free.line == 42
        assert isinstance(use_after_free.line, int)

    def test_cwe_extraction(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        use_after_free = next(v for v in vulns if "after it has been freed" in v.message)
        assert use_after_free.cwe == "CWE-416"

    def test_cwe_without_prefix_handled(self):
        """Should add CWE- prefix if only number provided"""
        json_data = """{
          "issues": [
            {
              "checkerName": "TEST",
              "severity": "High",
              "description": "Test issue",
              "strippedFilePath": "/test.c",
              "mainEventLineNumber": 1,
              "cwe": "120"
            }
          ]
        }"""
        path = _write_coverity_json(json_data)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert vulns[0].cwe == "CWE-120"

    def test_alternate_json_format_warnings_key(self):
        """Should handle JSON with 'warnings' key instead of 'issues'"""
        path = _write_coverity_json(VALID_COVERITY_JSON_ALTERNATE)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 1
        assert vulns[0].message == "Buffer overflow in strcpy call"
        assert vulns[0].severity == "High"
        assert vulns[0].cwe == "CWE-120"

    def test_alternate_severity_critical_to_high(self):
        """Critical severity should map to High"""
        json_data = """{
          "issues": [{"checkerName": "TEST", "severity": "Critical", "description": "test", "strippedFilePath": "/test.c", "mainEventLineNumber": 1}]
        }"""
        path = _write_coverity_json(json_data)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert vulns[0].severity == "High"

    def test_alternate_severity_serious_to_high(self):
        """Serious severity should map to High"""
        json_data = """{
          "issues": [{"checkerName": "TEST", "severity": "Serious", "description": "test", "strippedFilePath": "/test.c", "mainEventLineNumber": 1}]
        }"""
        path = _write_coverity_json(json_data)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert vulns[0].severity == "High"

    def test_numeric_severity_mapping(self):
        """Numeric severities should map correctly"""
        json_data = """{
          "issues": [
            {"checkerName": "T1", "severity": "5", "description": "test", "strippedFilePath": "/test.c", "mainEventLineNumber": 1},
            {"checkerName": "T2", "severity": "3", "description": "test", "strippedFilePath": "/test.c", "mainEventLineNumber": 2},
            {"checkerName": "T3", "severity": "1", "description": "test", "strippedFilePath": "/test.c", "mainEventLineNumber": 3}
          ]
        }"""
        path = _write_coverity_json(json_data)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert vulns[0].severity == "Critical"
        assert vulns[1].severity == "Medium"
        assert vulns[2].severity == "Info"

    def test_tool_field_is_coverity(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert all(v.tool == "coverity" for v in vulns)

    def test_empty_issues_returns_empty_list(self):
        json_data = '{"issues": []}'
        path = _write_coverity_json(json_data)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert vulns == []

    def test_missing_fields_handled_gracefully(self):
        json_data = """{
          "issues": [
            {
              "checkerName": "TEST",
              "description": "Test issue"
            }
          ]
        }"""
        path = _write_coverity_json(json_data)
        try:
            vulns = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 1
        assert vulns[0].file is None
        assert vulns[0].line is None
        assert vulns[0].severity == "Info"

    def test_safe_parse_on_missing_file(self):
        parser = CoverityParser()
        result = parser.safe_parse("/nonexistent/path/coverity.json")
        assert result == []

    def test_safe_parse_on_invalid_json(self):
        path = _write_coverity_json("{not valid json}")
        try:
            result = CoverityParser().safe_parse(path)
        finally:
            os.unlink(path)
        assert result == []

    def test_raises_value_error_on_non_string_input(self):
        with pytest.raises(ValueError, match="expects a file path"):
            CoverityParser().parse(12345)

    def test_standalone_function_returns_same_as_class(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            from_fn = parse_coverity_json(path)
            from_class = CoverityParser().parse(path)
        finally:
            os.unlink(path)
        assert len(from_fn) == len(from_class)
        for a, b in zip(from_fn, from_class):
            assert a.message == b.message
            assert a.severity == b.severity
            assert a.cwe == b.cwe

    def test_integration_with_base_parser_summary(self):
        path = _write_coverity_json(VALID_COVERITY_JSON)
        try:
            parser = CoverityParser()
            vulns = parser.parse(path)
            summary = parser.summary(vulns)
        finally:
            os.unlink(path)
        assert summary["High"] == 1
        assert summary["Medium"] == 1
        assert summary["Low"] == 1
        assert summary["Info"] == 1


# ===========================================================================
# GCCAnalyzerParser tests
# ===========================================================================

class TestGCCAnalyzerParser:

    def test_tool_name_is_gcc_analyzer(self):
        assert GCCAnalyzerParser.tool_name == "gcc_analyzer"

    def test_is_subclass_of_base_parser(self):
        assert issubclass(GCCAnalyzerParser, BaseParser)

    def test_parse_from_file_returns_correct_count(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        assert len(vulns) == 5

    def test_parse_from_string_returns_correct_count(self):
        vulns = GCCAnalyzerParser().parse(VALID_GCC_OUTPUT)
        assert len(vulns) == 5

    def test_short_format_parsing(self):
        vulns = GCCAnalyzerParser().parse(VALID_GCC_OUTPUT_SHORT)
        assert len(vulns) == 3

    def test_severity_mapping_null_dereference_to_high(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        null_deref = next(v for v in vulns if "null-dereference" in v.vulnerability_type.lower() or "NULL" in v.message)
        assert null_deref.severity == "High"

    def test_severity_mapping_use_after_free_to_high(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        use_after_free = next(v for v in vulns if "use after free" in v.message.lower())
        assert use_after_free.severity == "High"

    def test_severity_mapping_file_leak_to_medium(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        file_leak = next(v for v in vulns if "leak" in v.message.lower())
        assert file_leak.severity == "Medium"

    def test_severity_mapping_format_string_to_medium(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        format_vuln = next(v for v in vulns if "format" in v.message.lower())
        assert format_vuln.severity == "Medium"

    def test_severity_mapping_uninitialized_to_medium(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        uninit = next(v for v in vulns if "uninitialized" in v.message.lower())
        assert uninit.severity == "Medium"

    def test_file_path_extraction(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        null_deref = next(v for v in vulns if "NULL" in v.message)
        assert null_deref.file == "/home/user/project/src/main.c"

    def test_line_number_extraction(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        null_deref = next(v for v in vulns if "NULL" in v.message)
        assert null_deref.line == 42
        assert isinstance(null_deref.line, int)

    def test_cwe_extraction_from_message(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        null_deref = next(v for v in vulns if "NULL" in v.message)
        assert null_deref.cwe == "CWE-476"
        
        file_leak = next(v for v in vulns if "leak" in v.message.lower())
        assert file_leak.cwe == "CWE-404"

    def test_analyzer_type_extraction(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        null_deref = next(v for v in vulns if "NULL" in v.message)
        assert "null" in null_deref.vulnerability_type.lower()

    def test_tool_field_is_gcc_analyzer(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            vulns = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        assert all(v.tool == "gcc_analyzer" for v in vulns)

    def test_empty_output_returns_empty_list(self):
        vulns = GCCAnalyzerParser().parse("")
        assert vulns == []

    def test_output_without_analyzer_warnings_returns_empty(self):
        output = "No warnings found.\nCompilation successful.\n"
        vulns = GCCAnalyzerParser().parse(output)
        assert vulns == []

    def test_non_analyzer_warnings_ignored(self):
        output = """/test/file.c:10:5: warning: unused variable 'x' [-Wunused-variable]
/test/file.c:20:3: warning: implicit declaration of function 'foo' [-Wimplicit-function-declaration]
"""
        vulns = GCCAnalyzerParser().parse(output)
        assert vulns == []

    def test_mixed_warnings_only_analyzer_parsed(self):
        output = """/test/file.c:10:5: warning: unused variable 'x' [-Wunused-variable]
/test/file.c:20:5: warning: use after free [-Wanalyzer-use-after-free]
/test/file.c:30:3: warning: implicit declaration [-Wimplicit-function-declaration]
"""
        vulns = GCCAnalyzerParser().parse(output)
        assert len(vulns) == 1
        assert "use after free" in vulns[0].message.lower()

    def test_error_severity_mapped_to_high(self):
        output = """/test/file.c:42:5: error: use after free [-Wanalyzer-use-after-free]"""
        vulns = GCCAnalyzerParser().parse(output)
        assert len(vulns) == 1
        assert vulns[0].severity == "High"

    def test_note_severity_mapped_to_info(self):
        output = """/test/file.c:42:5: note: pointer freed here [-Wanalyzer-use-after-free]"""
        vulns = GCCAnalyzerParser().parse(output)
        assert len(vulns) == 1
        assert vulns[0].severity == "Info"

    def test_safe_parse_on_missing_file(self):
        parser = GCCAnalyzerParser()
        result = parser.safe_parse("/nonexistent/path/gcc_output.txt")
        assert result == []

    def test_safe_parse_with_string_input(self):
        parser = GCCAnalyzerParser()
        result = parser.safe_parse(VALID_GCC_OUTPUT)
        assert len(result) == 5

    def test_raises_value_error_on_non_string_input(self):
        with pytest.raises(ValueError, match="expects a string"):
            GCCAnalyzerParser().parse(12345)

    def test_standalone_function_returns_same_as_class(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            from_fn = parse_gcc_analyzer_output(path)
            from_class = GCCAnalyzerParser().parse(path)
        finally:
            os.unlink(path)
        assert len(from_fn) == len(from_class)
        for a, b in zip(from_fn, from_class):
            assert a.message == b.message
            assert a.severity == b.severity
            assert a.file == b.file
            assert a.line == b.line

    def test_integration_with_base_parser_summary(self):
        path = _write_gcc_output(VALID_GCC_OUTPUT)
        try:
            parser = GCCAnalyzerParser()
            vulns = parser.parse(path)
            summary = parser.summary(vulns)
        finally:
            os.unlink(path)
        assert summary["High"] == 2  # null-dereference, use-after-free
        assert summary["Medium"] == 3  # file-leak, format-string, uninitialized

    def test_deduplication_of_warnings(self):
        """Should not create duplicate entries for the same warning"""
        output_with_duplicate = """/test/file.c:42:5: warning: use after free [-Wanalyzer-use-after-free]
/test/file.c: In function 'main':
/test/file.c:42:5: warning: use after free [-Wanalyzer-use-after-free]
   42 |     free(ptr);
      |     ^~~~~~~~~
"""
        vulns = GCCAnalyzerParser().parse(output_with_duplicate)
        assert len(vulns) == 1

    def test_multiline_format_parsing(self):
        """Should handle the multiline format with 'In function' lines"""
        output = """/test/file.c: In function 'process_data':
/test/file.c:108:10: warning: leak of 'fp' [-Wanalyzer-file-leak]
  108 |     return;
      |          ^
"""
        vulns = GCCAnalyzerParser().parse(output)
        assert len(vulns) == 1
        assert vulns[0].file == "/test/file.c"
        assert vulns[0].line == 108
        assert "leak" in vulns[0].message.lower()