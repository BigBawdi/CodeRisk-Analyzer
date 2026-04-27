"""
analysis_service.py — Orchestrates running security analysis tools
and collecting their results into a unified AnalysisResult.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
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
# Utility
# ---------------------------------------------------------------------------

def _is_tool_available(executable: str) -> bool:
    """Return True if the given executable exists in PATH."""
    return shutil.which(executable) is not None


def _resolve_gcc_targets(target: str) -> List[str]:
    """
    Expand a file or directory into a list of C/C++ source files.
    GCC cannot analyze directories directly.
    """
    p = Path(target)
    if p.is_file():
        return [str(p)]

    sources: List[str] = []
    for ext in ("*.c", "*.cpp", "*.cxx", "*.cc"):
        sources.extend(str(f) for f in p.rglob(ext))
    return sorted(sources)


def _merge_gcc_json_chunks(chunks: List[str]) -> str:
    """Merge multiple GCC JSON diagnostic arrays into one JSON array string."""
    merged: list = []
    for chunk in chunks:
        start = chunk.find("[")
        end   = chunk.rfind("]")
        if start == -1 or end == -1 or end < start:
            logger.debug("No JSON array found in gcc chunk; skipping.")
            continue
        try:
            items = json.loads(chunk[start:end + 1])
            if isinstance(items, list):
                merged.extend(items)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse gcc JSON chunk: %s", exc)
    return json.dumps(merged if merged else [])


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Outcome of running a single tool against a target file/directory."""
    tool_id: str
    findings: List[Vulnerability] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None
    return_code: Optional[int] = None
    raw_output_path: Optional[str] = None
    raw_output: Optional[str] = None  # populated when keep_raw_output=True

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
            "target":         self.target,
            "tools_run":      [tr.tool_id for tr in self.tool_results],
            "tools_failed":   [tr.tool_id for tr in self.tool_results if not tr.success],
            "total_findings": len(self.all_findings),
            "by_severity":    counts,
            "by_tool":        {tr.tool_id: tr.finding_count for tr in self.tool_results},
        }


# ---------------------------------------------------------------------------
# Tool command builders
# ---------------------------------------------------------------------------

def _cppcheck_cmd(target: str, output_path: Optional[str]) -> List[str]:
    return [
        "cppcheck",
        "--xml", "--xml-version=2",
        "--enable=all",
        "--suppress=missingIncludeSystem",
        f"--output-file={output_path}",
        target,
    ]


def _flawfinder_cmd(target: str, output_path: Optional[str]) -> List[str]:
    return ["flawfinder", "--columns", "--dataonly", "--quiet", target]


def _gcc_analyzer_cmd(target: str, output_path: Optional[str]) -> List[str]:
    return [
        "gcc",
        "-fanalyzer",
        "-fdiagnostics-format=json",
        "-Wall", "-Wextra",
        "-c",
        "-o", os.devnull,  # cross-platform null output
        target,
    ]


# Step 1 - build capture
def _coverity_build_cmd(target: str, output_path: str) -> List[str]:
    return [
        "cov-build",
        "--dir", output_path,
        "gcc", "-c", target
    ]

# Step 2 - analyze
def _coverity_cmd(target: str, output_path: str) -> List[str]:
    return [
        "cov-analyze",
        "--dir", output_path,
        "--all",
        "--json-output-v10", os.path.join(output_path, "results.json"),
    ]


# ---------------------------------------------------------------------------
# Tool configuration registry
# ---------------------------------------------------------------------------

@dataclass
class ToolConfig:
    """Describes how to invoke a tool and capture its output."""
    output_mode: str = "file"    # "file" | "stdout" | "stderr"
    output_ext:  str = ".txt"    # temp file extension
    build_cmd:   Any = None      # Callable[[str, Optional[str]], List[str]]


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
        # GCC writes diagnostics (including JSON) to stderr regardless of format flag
        output_mode="stderr",
        output_ext=".json",
        build_cmd=_gcc_analyzer_cmd,
    ),
    "coverity": ToolConfig(
        output_mode="file",
        output_ext=".json",
        build_cmd=_coverity_cmd,
    ),
}

TOOL_EXECUTABLES: Dict[str, str] = {
    "cppcheck":     "cppcheck",
    "flawfinder":   "flawfinder",
    "gcc_analyzer": "gcc",
    "coverity":     "cov-analyze",
}


# ---------------------------------------------------------------------------
# AnalysisService
# ---------------------------------------------------------------------------

class AnalysisService:
    """Runs selected analysis tools against a target and returns unified results."""

    def __init__(
        self,
        timeout: int = 120,
        keep_raw_output: bool = False,
        tool_configs: Optional[Dict[str, ToolConfig]] = None,
    ):
        self.timeout = timeout
        self.keep_raw_output = keep_raw_output
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
        """Run all selected tools against target and return aggregated results."""
        target = str(target)
        tools  = selected_tools if selected_tools is not None else list(self._parsers.keys())

        if not os.path.exists(target):
            raise FileNotFoundError(f"Analysis target not found: {target!r}")

        result = AnalysisResult(target=target)
        for tool_id in tools:
            tool_result = self._run_tool(tool_id, target)
            result.tool_results.append(tool_result)
            status = "ok" if tool_result.success else f"FAILED ({tool_result.error})"
            logger.info("[%s] %s — %d finding(s)", tool_id, status, tool_result.finding_count)

        return result

    def available_tools(self) -> List[str]:
        """Return the list of supported tool IDs."""
        return list(self._parsers.keys())

    # ------------------------------------------------------------------
    # Internal — tool runner
    # ------------------------------------------------------------------

    def _run_tool(self, tool_id: str, target: str) -> ToolResult:
        # Run a single tool and parse its output.

        # Guard: tool must be registered
        if tool_id not in self._parsers:
            logger.warning("Unknown tool_id %r — skipping.", tool_id)
            return ToolResult(tool_id=tool_id, success=False, error=f"Unknown tool: {tool_id!r}")

        # Guard: executable must be on PATH
        executable = TOOL_EXECUTABLES.get(tool_id)
        if executable and not _is_tool_available(executable):
            return ToolResult(
                tool_id=tool_id,
                success=False,
                error=f"'{executable}' is not installed or not in PATH",
            )

        cfg = self._configs.get(tool_id)
        if cfg is None:
            return ToolResult(tool_id=tool_id, success=False, error="No ToolConfig registered")

        # Invoke the tool
        try:
            raw_text, return_code, output_path = self._invoke(tool_id, cfg, target)
        except FileNotFoundError:
            return ToolResult(tool_id=tool_id, success=False,
                              error=f"'{tool_id}' is not installed or not in PATH")
        except subprocess.TimeoutExpired:
            return ToolResult(tool_id=tool_id, success=False,
                              error=f"'{tool_id}' timed out after {self.timeout}s")
        except Exception as exc:
            logger.exception("Failed to invoke tool %r", tool_id)
            return ToolResult(tool_id=tool_id, success=False, error=str(exc))

        if return_code not in (0, 1):
            logger.warning("[%s] exited with code %d (continuing anyway)", tool_id, return_code)

        # Parse output
        try:
            if cfg.output_mode == "file":
                if tool_id == "coverity":
                    parse_input = os.path.join(output_path, "results.json")
                else:
                    parse_input = output_path or ""
            else:
                # stdout and stderr tools pass raw text directly to the parser
                parse_input = raw_text or ""
            findings = self._parsers[tool_id].safe_parse(parse_input)
        except Exception as exc:
            logger.exception("[%s] parser raised unexpectedly", tool_id)
            return ToolResult(
                tool_id=tool_id,
                success=False,
                error=f"Parser error: {exc}",
                return_code=return_code,
                raw_output_path=output_path,
            )
        finally:
            if output_path and not self.keep_raw_output:
                try:
                    os.unlink(output_path)
                except OSError as e:
                    logger.debug("Failed to delete temp file %s: %s", output_path, e)

        return ToolResult(
            tool_id=tool_id,
            findings=findings,
            success=True,
            return_code=return_code,
            raw_output_path=output_path if self.keep_raw_output else None,
            raw_output=raw_text   if self.keep_raw_output else None,
        )

    # ------------------------------------------------------------------
    # Internal — subprocess invocation
    # ------------------------------------------------------------------

    def _invoke(
        self,
        tool_id: str,
        cfg: ToolConfig,
        target: str,
    ) -> tuple[str, int, Optional[str]]:
        """Invoke the tool subprocess and return (raw_text, return_code, output_path)."""

        output_path: Optional[str] = None
        raw_text: str = ""

        if cfg.output_mode == "file":
            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            os.close(fd)
            proc = self._run_subprocess(cfg.build_cmd(target, output_path))
            try:
                with open(output_path, "r", encoding="utf-8", errors="replace") as fh:
                    raw_text = fh.read()
            except OSError:
                raw_text = ""

        elif cfg.output_mode == "stdout":
            proc = self._run_subprocess(cfg.build_cmd(target, None))
            raw_text = proc.stdout or ""
            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(raw_text)

        elif cfg.output_mode == "stderr":
            if tool_id == "gcc_analyzer":
                return self._invoke_gcc(cfg, target)

            proc = self._run_subprocess(cfg.build_cmd(target, None))
            raw_text = proc.stderr or ""
            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(raw_text)

        else:
            raise ValueError(f"Unknown output_mode {cfg.output_mode!r} for tool {tool_id!r}")

        return raw_text, proc.returncode, output_path

    def _invoke_gcc(
        self,
        cfg: ToolConfig,
        target: str,
    ) -> tuple[str, int, Optional[str]]:
        """Handle GCC's multi-file stderr JSON output as a special case."""
        source_files = _resolve_gcc_targets(target)

        if not source_files:
            logger.warning("[gcc_analyzer] No C/C++ source files found in %s", target)
            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("[]")
            return "[]", 0, output_path

        all_diagnostics: List[str] = []
        last_rc = 0

        for src in source_files:
            proc  = self._run_subprocess(cfg.build_cmd(src, None))
            chunk = proc.stderr or ""
            if chunk.strip():
                all_diagnostics.append(chunk.strip())
            if proc.returncode not in (0, 1):
                last_rc = max(last_rc, proc.returncode)

        raw_text = _merge_gcc_json_chunks(all_diagnostics)
        fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(raw_text)

        return raw_text, last_rc, output_path

    def _run_subprocess(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run a command and capture stdout + stderr."""
        logger.debug("Running: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=self.timeout,
        )