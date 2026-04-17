"""
services/analysis_service.py

Orchestrates running static analysis tools via subprocess, feeding their
raw output to the appropriate parser, and aggregating the results.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.parsers.cppcheck_parser import CppcheckParser
from backend.parsers.flawfinder_parser import FlawfinderParser
from backend.parsers.gccCompiler_parser import GCCAnalyzerParser
from backend.parsers.coverity_parser import CoverityParser
from backend.normalization.vulnerability_schema import Vulnerability

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Outcome of running a single tool against a target file/directory."""
    tool_id: str
    findings: List[Vulnerability] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None
    return_code: Optional[int] = None
    raw_output_path: Optional[str] = None  # path to temp file kept for debugging

    @property
    def finding_count(self) -> int:
        return len(self.findings)


@dataclass
class AnalysisResult:
    """Aggregated result across all tools run in one analysis pass."""
    target: str
    tool_results: List[ToolResult] = field(default_factory=list)

    @property
    def all_findings(self) -> List[Vulnerability]:
        return [f for tr in self.tool_results for f in tr.findings]

    @property
    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "target": self.target,
            "tools_run": [tr.tool_id for tr in self.tool_results],
            "tools_failed": [tr.tool_id for tr in self.tool_results if not tr.success],
            "total_findings": len(self.all_findings),
            "by_severity": counts,
            "by_tool": {tr.tool_id: tr.finding_count for tr in self.tool_results},
        }


# ---------------------------------------------------------------------------
# Per-tool runner config
# ---------------------------------------------------------------------------

@dataclass
class ToolConfig:
    """Describes how to invoke a tool and where to find its output."""
    # Output format fed to the parser: "file" or "stdout"
    output_mode: str = "file"
    # File extension for the temp output file (used when output_mode="file")
    output_ext: str = ".txt"
    # A callable(target, output_path) -> List[str] that builds the CLI command.
    # output_path is None when output_mode="stdout".
    build_cmd: Any = None  # Callable[[str, Optional[str]], List[str]]


def _cppcheck_cmd(target: str, output_path: str) -> List[str]:
    return [
        "cppcheck",
        "--xml", "--xml-version=2",
        "--enable=all",
        "--suppress=missingIncludeSystem",
        f"--output-file={output_path}",
        target,
    ]


def _flawfinder_cmd(target: str, output_path: str) -> List[str]:
    # Flawfinder writes to stdout; we redirect via the runner.
    return ["flawfinder", "--dataonly", "--quiet", target]


def _gcc_analyzer_cmd(target: str, output_path: str) -> List[str]:
    # gcc -fanalyzer writes diagnostics to stderr; captured by the runner.
    return [
        "gcc",
        "-fanalyzer",
        "-fanalyzer-checker=all",
        "-Wall",
        "-c",           # compile only, no link
        "-o", "/dev/null",
        target,
    ]


def _coverity_cmd(target: str, output_path: str) -> List[str]:
    # cov-analyze writes JSON to the output path.
    return [
        "cov-analyze",
        "--dir", output_path,   # output_path is a directory here; handled specially
        "--all",
        "--json-output-v10", os.path.join(output_path, "results.json"),
    ]


TOOL_CONFIGS: Dict[str, ToolConfig] = {
    "cppcheck": ToolConfig(
        output_mode="file",
        output_ext=".xml",
        build_cmd=_cppcheck_cmd,
    ),
    "flawfinder": ToolConfig(
        output_mode="stdout",
        output_ext=".txt",
        build_cmd=_flawfinder_cmd,
    ),
    "gcc_analyzer": ToolConfig(
        output_mode="stderr",   # gcc -fanalyzer writes to stderr
        output_ext=".txt",
        build_cmd=_gcc_analyzer_cmd,
    ),
    "coverity": ToolConfig(
        output_mode="file",
        output_ext=".json",
        build_cmd=_coverity_cmd,
    ),
}


# ---------------------------------------------------------------------------
# AnalysisService
# ---------------------------------------------------------------------------

class AnalysisService:
    """
    Runs static analysis tools against a target and parses their output.

    Usage
    -----
    service = AnalysisService()
    result  = service.run_full_analysis("/path/to/project", ["cppcheck", "flawfinder"])
    print(result.summary)
    for finding in result.all_findings:
        print(finding)
    """

    def __init__(
        self,
        timeout: int = 120,
        keep_raw_output: bool = False,
        tool_configs: Optional[Dict[str, ToolConfig]] = None,
    ):
        """
        Parameters
        ----------
        timeout : int
            Seconds before a tool subprocess is killed (default 120).
        keep_raw_output : bool
            If True, temp files with raw tool output are NOT deleted after
            parsing — useful for debugging.
        tool_configs : dict, optional
            Override the default TOOL_CONFIGS for specific tools.
        """
        self.timeout = timeout
        self.keep_raw_output = keep_raw_output

        # Merge caller overrides on top of defaults
        self._configs: Dict[str, ToolConfig] = {**TOOL_CONFIGS, **(tool_configs or {})}

        self._parsers = {
            "cppcheck":     CppcheckParser(),
            "flawfinder":   FlawfinderParser(),
            "gcc_analyzer": GCCAnalyzerParser(),
            "coverity":     CoverityParser(),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_full_analysis(
        self,
        target: str,
        selected_tools: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """
        Run each requested tool against *target* and return an AnalysisResult.

        Parameters
        ----------
        target : str
            Path to a source file or directory to analyse.
        selected_tools : list of str, optional
            Tool IDs to run.  Defaults to all registered tools.
            Unknown IDs are logged and skipped.
        """
        target = str(target)
        tools = selected_tools if selected_tools is not None else list(self._parsers.keys())

        if not os.path.exists(target):
            raise FileNotFoundError(f"Analysis target not found: {target!r}")

        result = AnalysisResult(target=target)

        for tool_id in tools:
            tool_result = self._run_tool(tool_id, target)
            result.tool_results.append(tool_result)
            status = "ok" if tool_result.success else f"FAILED ({tool_result.error})"
            logger.info(
                "[%s] %s — %d finding(s)",
                tool_id, status, tool_result.finding_count,
            )

        return result

    def available_tools(self) -> List[str]:
        """Return the list of tool IDs this service knows about."""
        return list(self._parsers.keys())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_tool(self, tool_id: str, target: str) -> ToolResult:
        """Run a single tool and parse its output. Never raises."""
        if tool_id not in self._parsers:
            logger.warning("Unknown tool_id %r — skipping.", tool_id)
            return ToolResult(tool_id=tool_id, success=False, error=f"Unknown tool: {tool_id!r}")

        cfg = self._configs.get(tool_id)
        if cfg is None:
            logger.warning("No ToolConfig for %r — skipping.", tool_id)
            return ToolResult(tool_id=tool_id, success=False, error="No ToolConfig registered")

        try:
            raw_text, return_code, output_path = self._invoke(tool_id, cfg, target)
        except Exception as exc:
            logger.exception("Failed to invoke tool %r", tool_id)
            return ToolResult(tool_id=tool_id, success=False, error=str(exc))

        # Treat non-zero exit as a warning, not a hard failure — most tools
        # return 1 when they find issues, which is the normal case.
        if return_code not in (0, 1):
            logger.warning("[%s] exited with code %d", tool_id, return_code)

        # Parse
        parser = self._parsers[tool_id]
        try:
            # GCCAnalyzerParser accepts raw string directly;
            # file-based parsers accept a path; both are handled by safe_parse.
            parse_input = output_path if output_path else raw_text
            findings = parser.safe_parse(parse_input)
        except Exception as exc:
            logger.exception("[%s] parser raised unexpectedly", tool_id)
            findings = []
            return ToolResult(
                tool_id=tool_id,
                success=False,
                error=f"Parser error: {exc}",
                return_code=return_code,
                raw_output_path=output_path,
            )
        finally:
            # Clean up temp file unless the caller asked to keep it
            if output_path and not self.keep_raw_output:
                try:
                    os.unlink(output_path)
                except OSError:
                    pass

        return ToolResult(
            tool_id=tool_id,
            findings=findings,
            success=True,
            return_code=return_code,
            raw_output_path=output_path if self.keep_raw_output else None,
        )

    def _invoke(
        self,
        tool_id: str,
        cfg: ToolConfig,
        target: str,
    ) -> tuple[str, int, Optional[str]]:
        """
        Build the command, run it, and return (raw_text, return_code, output_path).

        output_path is a path to a temp file when output_mode=="file", else None.
        raw_text is the captured stdout/stderr when output_mode is "stdout"/"stderr".
        """
        output_path: Optional[str] = None
        raw_text: str = ""

        if cfg.output_mode == "file":
            # Tool writes its output to a file we specify on the command line.
            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            os.close(fd)
            cmd = cfg.build_cmd(target, output_path)
            proc = self._run_subprocess(cmd)
            # Read whatever landed in the file
            try:
                with open(output_path, "r", encoding="utf-8", errors="ignore") as fh:
                    raw_text = fh.read()
            except OSError:
                raw_text = ""

        elif cfg.output_mode == "stdout":
            cmd = cfg.build_cmd(target, None)
            proc = self._run_subprocess(cmd)
            raw_text = proc.stdout or ""
            # Write to temp file so file-based parsers can read it
            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(raw_text)

        elif cfg.output_mode == "stderr":
            cmd = cfg.build_cmd(target, None)
            proc = self._run_subprocess(cmd)
            # gcc -fanalyzer puts diagnostics on stderr
            raw_text = proc.stderr or ""
            # Write to temp file (or pass directly to parser if it accepts strings)
            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(raw_text)

        else:
            raise ValueError(f"Unknown output_mode {cfg.output_mode!r} for tool {tool_id!r}")

        return raw_text, proc.returncode, output_path

    def _run_subprocess(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run *cmd* with a timeout, capturing stdout + stderr."""
        logger.debug("Running: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=self.timeout,
        )