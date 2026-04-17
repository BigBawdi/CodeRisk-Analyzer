"""
tests/test_analysis_service.py

Tests for AnalysisService orchestrator.
"""

import os
import tempfile
import subprocess
import pytest
from unittest.mock import patch, MagicMock, call, mock_open

from backend.analysis.analysis_service import (
    AnalysisService,
    AnalysisResult,
    ToolResult,
    ToolConfig,
    TOOL_CONFIGS,
)
from backend.normalization.vulnerability_schema import Vulnerability
from backend.parsers.base_parser import BaseParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_vulnerabilities():
    """Return a list of sample Vulnerability objects."""
    return [
        Vulnerability(
            tool="cppcheck",
            file="test.c",
            line=10,
            vulnerability_type="Buffer Overflow",
            severity="High",
            message="Buffer overflow risk",
            cwe="CWE-120",
        ),
        Vulnerability(
            tool="cppcheck",
            file="test.c",
            line=20,
            vulnerability_type="Memory Leak",
            severity="Medium",
            message="Memory leak",
            cwe="CWE-401",
        ),
    ]


@pytest.fixture
def mock_parser(sample_vulnerabilities):
    """Return a mock parser that returns sample vulnerabilities."""
    parser = MagicMock(spec=BaseParser)
    parser.tool_name = "mock_tool"
    parser.safe_parse.return_value = sample_vulnerabilities
    parser.summary.return_value = {"High": 1, "Medium": 1}
    return parser


@pytest.fixture
def service_with_mocked_parsers(mock_parser):
    """Return AnalysisService with parsers replaced by mocks."""
    service = AnalysisService()
    service._parsers = {
        "cppcheck": mock_parser,
        "flawfinder": mock_parser,
        "gcc_analyzer": mock_parser,
        "coverity": mock_parser,
    }
    return service


@pytest.fixture
def temp_target_file():
    """Create a temporary C file for analysis target."""
    fd, path = tempfile.mkstemp(suffix=".c")
    with os.fdopen(fd, "w") as f:
        f.write("int main() { return 0; }")
    yield path
    os.unlink(path)


# ---------------------------------------------------------------------------
# Tests for ToolResult and AnalysisResult
# ---------------------------------------------------------------------------

class TestResultContainers:
    def test_tool_result_finding_count(self):
        findings = [Vulnerability(tool="t", file="f", line=1, vulnerability_type="X",
                                  severity="High", message="m")]
        tr = ToolResult(tool_id="test", findings=findings)
        assert tr.finding_count == 1

    def test_tool_result_defaults(self):
        tr = ToolResult(tool_id="test")
        assert tr.findings == []
        assert tr.success is True
        assert tr.error is None
        assert tr.return_code is None
        assert tr.raw_output_path is None

    def test_analysis_result_all_findings(self):
        findings1 = [Vulnerability(tool="t1", file="f", line=1, vulnerability_type="X",
                                   severity="High", message="m1")]
        findings2 = [Vulnerability(tool="t2", file="f", line=2, vulnerability_type="Y",
                                   severity="Low", message="m2")]
        tr1 = ToolResult(tool_id="t1", findings=findings1)
        tr2 = ToolResult(tool_id="t2", findings=findings2)
        ar = AnalysisResult(target="/tmp", tool_results=[tr1, tr2])
        assert len(ar.all_findings) == 2

    def test_analysis_result_summary(self):
        findings = [
            Vulnerability(tool="t1", file="f", line=1, vulnerability_type="X",
                          severity="High", message="m1"),
            Vulnerability(tool="t1", file="f", line=2, vulnerability_type="Y",
                          severity="High", message="m2"),
            Vulnerability(tool="t2", file="f", line=3, vulnerability_type="Z",
                          severity="Low", message="m3"),
        ]
        tr1 = ToolResult(tool_id="t1", findings=findings[:2], success=True)
        tr2 = ToolResult(tool_id="t2", findings=findings[2:], success=False, error="fail")
        ar = AnalysisResult(target="/tmp", tool_results=[tr1, tr2])
        summary = ar.summary
        assert summary["target"] == "/tmp"
        assert set(summary["tools_run"]) == {"t1", "t2"}
        assert summary["tools_failed"] == ["t2"]
        assert summary["total_findings"] == 3
        assert summary["by_severity"] == {"High": 2, "Low": 1}
        assert summary["by_tool"] == {"t1": 2, "t2": 1}


# ---------------------------------------------------------------------------
# Tests for AnalysisService initialization and configuration
# ---------------------------------------------------------------------------

class TestAnalysisServiceInit:
    def test_default_initialization(self):
        service = AnalysisService()
        assert service.timeout == 120
        assert service.keep_raw_output is False
        assert "cppcheck" in service._parsers
        assert "flawfinder" in service._parsers
        assert "gcc_analyzer" in service._parsers
        assert "coverity" in service._parsers

    def test_custom_timeout_and_keep_output(self):
        service = AnalysisService(timeout=60, keep_raw_output=True)
        assert service.timeout == 60
        assert service.keep_raw_output is True

    def test_override_tool_configs(self):
        custom_config = {"cppcheck": ToolConfig(output_mode="stdout", output_ext=".xml", build_cmd=lambda t, o: ["cppcheck", t])}
        service = AnalysisService(tool_configs=custom_config)
        assert service._configs["cppcheck"].output_mode == "stdout"

    def test_available_tools(self):
        service = AnalysisService()
        tools = service.available_tools()
        assert "cppcheck" in tools
        assert "flawfinder" in tools


# ---------------------------------------------------------------------------
# Tests for run_full_analysis
# ---------------------------------------------------------------------------

class TestRunFullAnalysis:
    def test_target_not_found(self):
        service = AnalysisService()
        with pytest.raises(FileNotFoundError, match="Analysis target not found"):
            service.run_full_analysis("/nonexistent/path")

    def test_runs_specific_tools(self, temp_target_file, service_with_mocked_parsers):
        with patch.object(service_with_mocked_parsers, "_run_tool") as mock_run:
            mock_run.return_value = ToolResult(tool_id="cppcheck", findings=[])
            service_with_mocked_parsers.run_full_analysis(temp_target_file, selected_tools=["cppcheck"])
            mock_run.assert_called_once_with("cppcheck", temp_target_file)

    def test_skips_unknown_tool(self, temp_target_file, service_with_mocked_parsers, caplog):
        result = service_with_mocked_parsers.run_full_analysis(
            temp_target_file, selected_tools=["unknown_tool"]
        )
        assert len(result.tool_results) == 1
        tr = result.tool_results[0]
        assert tr.tool_id == "unknown_tool"
        assert tr.success is False
        assert "Unknown tool" in tr.error
        assert "Unknown tool_id" in caplog.text

    def test_aggregates_results(self, temp_target_file, service_with_mocked_parsers, sample_vulnerabilities):
        # Mock _run_tool to return ToolResult with findings
        def mock_run(tool_id, target):
            return ToolResult(tool_id=tool_id, findings=sample_vulnerabilities)
        with patch.object(service_with_mocked_parsers, "_run_tool", side_effect=mock_run):
            result = service_with_mocked_parsers.run_full_analysis(
                temp_target_file, selected_tools=["cppcheck", "flawfinder"]
            )
        assert len(result.tool_results) == 2
        assert len(result.all_findings) == 4
        assert result.summary["by_tool"]["cppcheck"] == 2
        assert result.summary["by_tool"]["flawfinder"] == 2


# ---------------------------------------------------------------------------
# Tests for _run_tool (internal method)
# ---------------------------------------------------------------------------

class TestRunTool:
    def test_unknown_tool_id(self, service_with_mocked_parsers, temp_target_file):
        result = service_with_mocked_parsers._run_tool("unknown", temp_target_file)
        assert result.success is False
        assert "Unknown tool" in result.error

    def test_no_config_for_tool(self, service_with_mocked_parsers, temp_target_file):
        # Remove config for a known tool
        del service_with_mocked_parsers._configs["cppcheck"]
        result = service_with_mocked_parsers._run_tool("cppcheck", temp_target_file)
        assert result.success is False
        assert "No ToolConfig" in result.error

    def test_invoke_exception(self, service_with_mocked_parsers, temp_target_file):
        with patch.object(service_with_mocked_parsers, "_invoke", side_effect=Exception("boom")):
            result = service_with_mocked_parsers._run_tool("cppcheck", temp_target_file)
        assert result.success is False
        assert result.error == "boom"

    def test_parse_success(self, service_with_mocked_parsers, temp_target_file, sample_vulnerabilities):
        # Mock _invoke to return raw output and temp file path
        with patch.object(service_with_mocked_parsers, "_invoke") as mock_invoke:
            mock_invoke.return_value = ("raw output", 0, "/tmp/output.xml")
            result = service_with_mocked_parsers._run_tool("cppcheck", temp_target_file)

        assert result.success is True
        assert result.findings == sample_vulnerabilities
        assert result.return_code == 0
        assert result.raw_output_path is None  # because keep_raw_output=False

    def test_parser_exception(self, service_with_mocked_parsers, temp_target_file):
        with patch.object(service_with_mocked_parsers, "_invoke") as mock_invoke:
            mock_invoke.return_value = ("raw", 0, "/tmp/out.xml")
            # Make parser raise
            service_with_mocked_parsers._parsers["cppcheck"].safe_parse.side_effect = Exception("parse error")
            result = service_with_mocked_parsers._run_tool("cppcheck", temp_target_file)

        assert result.success is False
        assert "Parser error" in result.error
        assert result.findings == []

    def test_keep_raw_output_flag(self, service_with_mocked_parsers, temp_target_file):
        service_with_mocked_parsers.keep_raw_output = True
        with patch.object(service_with_mocked_parsers, "_invoke") as mock_invoke:
            mock_invoke.return_value = ("raw", 0, "/tmp/out.xml")
            result = service_with_mocked_parsers._run_tool("cppcheck", temp_target_file)
        assert result.raw_output_path == "/tmp/out.xml"

    def test_temp_file_cleanup(self, service_with_mocked_parsers, temp_target_file):
        # Ensure temp file is deleted after parsing
        temp_path = tempfile.mktemp(suffix=".xml")
        with patch.object(service_with_mocked_parsers, "_invoke") as mock_invoke:
            mock_invoke.return_value = ("raw", 0, temp_path)
            # Create dummy file so os.unlink works
            with open(temp_path, "w") as f:
                f.write("dummy")
            service_with_mocked_parsers._run_tool("cppcheck", temp_target_file)
        assert not os.path.exists(temp_path)

    def test_non_zero_return_code_not_failure(self, service_with_mocked_parsers, temp_target_file):
        with patch.object(service_with_mocked_parsers, "_invoke") as mock_invoke:
            mock_invoke.return_value = ("raw", 1, "/tmp/out.xml")
            result = service_with_mocked_parsers._run_tool("cppcheck", temp_target_file)
        assert result.success is True
        assert result.return_code == 1


# ---------------------------------------------------------------------------
# Tests for _invoke (subprocess handling)
# ---------------------------------------------------------------------------

class TestInvoke:
    def test_file_mode(self, service_with_mocked_parsers):
        # Use a real temp file to avoid mocking mkstemp
        cfg = ToolConfig(output_mode="file", output_ext=".xml", build_cmd=lambda t, o: ["echo", "hello", "-o", o])
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = ""
            mock_proc.stderr = ""
            mock_run.return_value = mock_proc

            raw_text, return_code, output_path = service_with_mocked_parsers._invoke(
                "test", cfg, "target.c"
            )
        assert return_code == 0
        assert os.path.exists(output_path)
        # Clean up
        os.unlink(output_path)

    def test_stdout_mode(self, service_with_mocked_parsers):
        cfg = ToolConfig(output_mode="stdout", output_ext=".txt", build_cmd=lambda t, o: ["echo", "hello"])
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "hello world"
            mock_proc.stderr = ""
            mock_run.return_value = mock_proc

            raw_text, return_code, output_path = service_with_mocked_parsers._invoke(
                "test", cfg, "target.c"
            )
        assert raw_text == "hello world"
        assert output_path is not None
        # Temp file should contain the stdout
        with open(output_path, "r") as f:
            assert f.read() == "hello world"
        os.unlink(output_path)

    def test_stderr_mode(self, service_with_mocked_parsers):
        cfg = ToolConfig(output_mode="stderr", output_ext=".txt", build_cmd=lambda t, o: ["gcc", "-c", t])
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.stdout = ""
            mock_proc.stderr = "error message"
            mock_run.return_value = mock_proc

            raw_text, return_code, output_path = service_with_mocked_parsers._invoke(
                "gcc_analyzer", cfg, "target.c"
            )
        assert raw_text == "error message"
        assert return_code == 1
        with open(output_path, "r") as f:
            assert f.read() == "error message"
        os.unlink(output_path)

    def test_unknown_output_mode(self, service_with_mocked_parsers):
        cfg = ToolConfig(output_mode="unknown", output_ext=".txt", build_cmd=lambda t, o: [])
        with pytest.raises(ValueError, match="Unknown output_mode"):
            service_with_mocked_parsers._invoke("test", cfg, "target.c")

    def test_subprocess_timeout(self, service_with_mocked_parsers):
        service_with_mocked_parsers.timeout = 1
        cfg = ToolConfig(output_mode="stdout", output_ext=".txt", build_cmd=lambda t, o: ["sleep", "10"])
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=1)):
            with pytest.raises(subprocess.TimeoutExpired):
                service_with_mocked_parsers._invoke("test", cfg, "target.c")


# ---------------------------------------------------------------------------
# Integration tests with real subprocess (if tools are installed)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists("/usr/bin/echo"), reason="Requires echo command")
class TestRealSubprocess:
    def test_real_command_execution(self):
        service = AnalysisService()
        cfg = ToolConfig(output_mode="stdout", output_ext=".txt", build_cmd=lambda t, o: ["echo", "test"])
        raw_text, return_code, output_path = service._invoke("test", cfg, "dummy")
        assert raw_text.strip() == "test"
        assert return_code == 0
        os.unlink(output_path)