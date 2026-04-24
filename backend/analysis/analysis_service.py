from __future__ import annotations
import shutil

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

def _is_tool_available(executable: str) -> bool:
    """Check whether a tool exists in PATH."""
    return shutil.which(executable) is not None


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
    raw_output_path: Optional[str] = None
    raw_output: Optional[str] = None  # stores raw text when keep_raw_output=True

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
    # Output format fed to the parser: "file", "stdout", or "stderr"
    output_mode: str = "file"
    # File extension for the temp output file
    output_ext: str = ".txt"
    # A callable(target, output_path) -> List[str] that builds the CLI command.
    # output_path is None when output_mode is "stdout" or "stderr".
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
    return ["flawfinder", "--columns", "--dataonly", "--quiet", target]


def _gcc_analyzer_cmd(target: str, output_path: str) -> List[str]:
    return [
        "gcc",
        "-fanalyzer",
        "-fdiagnostics-format=json",   # FIX: structured JSON on stderr; plain text was unparseable
        "-Wall",
        "-Wextra",
        "-c",           # compile only, no link
        "-o", "/dev/null",
        target,
    ]


def _coverity_cmd(target: str, output_path: str) -> List[str]:
    return [
        "cov-analyze",
        "--dir", output_path,
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
        # GCC always writes diagnostics (including JSON) to stderr regardless
        # of -fdiagnostics-format.  output_mode="stderr" captures that stream.
        output_mode="stderr",
        output_ext=".json",            # FIX: reflect the actual content type
        build_cmd=_gcc_analyzer_cmd,
    ),
    "coverity": ToolConfig(
        output_mode="file",
        output_ext=".json",
        build_cmd=_coverity_cmd,
    ),
}

TOOL_EXECUTABLES = {
    "cppcheck": "cppcheck",
    "flawfinder": "flawfinder",
    "gcc_analyzer": "gcc",
    "coverity": "cov-analyze",
}


# ---------------------------------------------------------------------------
# AnalysisService
# ---------------------------------------------------------------------------

class AnalysisService:
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
        return list(self._parsers.keys())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_tool(self, tool_id: str, target: str) -> ToolResult:

        executable = TOOL_EXECUTABLES.get(tool_id)
        if executable and not _is_tool_available(executable):
            return ToolResult(
                tool_id=tool_id,
                success=False,
                error=f"Tool '{executable}' is not installed or not in PATH"
            )
        
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
        except FileNotFoundError:
            return ToolResult(
                tool_id=tool_id,
                success=False,
                error=f"Tool '{tool_id}' is not installed or not in PATH"
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_id=tool_id,
                success=False,
                error=f"Tool '{tool_id}' timed out after {self.timeout}s"
            )
        except Exception as exc:
            logger.exception("Failed to invoke tool %r", tool_id)
            return ToolResult(tool_id=tool_id, success=False, error=str(exc))

        if return_code not in (0, 1):
            logger.warning("[%s] exited with code %d (continuing anyway)", tool_id, return_code)

        parser = self._parsers[tool_id]

        try:
            parse_input = raw_text if raw_text else (output_path or "")
            findings = parser.safe_parse(parse_input)
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
            raw_output=raw_text if self.keep_raw_output else None,
        )

    def _invoke(
        self,
        tool_id: str,
        cfg: ToolConfig,
        target: str,
    ) -> tuple[str, int, Optional[str]]:

        output_path: Optional[str] = None
        raw_text: str = ""

        if cfg.output_mode == "file":
            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            os.close(fd)

            cmd = cfg.build_cmd(target, output_path)
            proc = self._run_subprocess(cmd)

            try:
                with open(output_path, "r", encoding="utf-8", errors="replace") as fh:
                    raw_text = fh.read()
            except OSError:
                raw_text = ""

        elif cfg.output_mode == "stdout":
            cmd = cfg.build_cmd(target, None)
            proc = self._run_subprocess(cmd)

            raw_text = proc.stdout or ""

            fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(raw_text)

        elif cfg.output_mode == "stderr":
            if tool_id == "gcc_analyzer":
                source_files = _resolve_gcc_targets(target)

                if not source_files:
                    logger.warning("[gcc_analyzer] No C/C++ source files found in %s", target)
                    fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        fh.write("[]")
                    return "[]", 0, output_path

                all_diagnostics: list[str] = []
                last_rc = 0

                for src in source_files:
                    cmd = cfg.build_cmd(src, None)
                    proc = self._run_subprocess(cmd)

                    chunk = proc.stderr or ""

                    if chunk.strip():
                        all_diagnostics.append(chunk.strip())

                    # ✅ FIX 5: Preserve highest severity return code
                    if proc.returncode not in (0, 1):
                        last_rc = max(last_rc, proc.returncode)

                raw_text = _merge_gcc_json_chunks(all_diagnostics)

                fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(raw_text)

                return raw_text, last_rc, output_path

            else:
                cmd = cfg.build_cmd(target, None)
                proc = self._run_subprocess(cmd)

                raw_text = proc.stderr or ""

                fd, output_path = tempfile.mkstemp(suffix=cfg.output_ext)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(raw_text)

                return raw_text, proc.returncode, output_path

        else:
            raise ValueError(f"Unknown output_mode {cfg.output_mode!r} for tool {tool_id!r}")

        return raw_text, proc.returncode, output_path

    def _run_subprocess(self, cmd: List[str]) -> subprocess.CompletedProcess:
        logger.debug("Running: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=self.timeout,
        )
    from pathlib import Path
from typing import List

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


# ---------------------------------------------------------------------------
# GCC helpers (minor robustness fix only)
# ---------------------------------------------------------------------------

def _merge_gcc_json_chunks(chunks: List[str]) -> str:
    import json

    merged: list = []

    for chunk in chunks:
        start = chunk.find("[")
        end   = chunk.rfind("]")

        if start == -1 or end == -1 or end < start:
            logger.debug("No JSON array found in gcc chunk; skipping.")
            continue

        try:
            items = json.loads(chunk[start : end + 1])
            if isinstance(items, list):
                merged.extend(items)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse gcc JSON chunk: %s", exc)

    return json.dumps(merged if merged else [])