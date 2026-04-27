"""
main.py — Entry point for the CodeRisk Analyzer application.
Imports the GUI class from gui.py and wires it to the AnalysisService backend.
"""

import sys
import logging
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QMessageBox, QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont

from GUI import CodeRiskAnalyzerGUI
from backend.analysis.analysis_service import AnalysisService, AnalysisResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool map — connects combo box display names to backend tool IDs
# ---------------------------------------------------------------------------
TOOL_MAP = {
    "Cppcheck":     "cppcheck",
    "Flawfinder":   "flawfinder",
    "GCC Analyzer": "gcc_analyzer",
    "Coverity":     "coverity",
}

# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

class AnalysisWorker(QThread):
    finished = pyqtSignal(object)
    error    = pyqtSignal(str)

    def __init__(self, target: str, tools: list):
        super().__init__()
        self.target = target
        self.tools  = tools

    def run(self):
        try:
            service = AnalysisService(timeout=600, keep_raw_output=True)
            result  = service.run_full_analysis(self.target, self.tools)
            self.finished.emit(result)
        except FileNotFoundError as exc:
            self.error.emit(f"Target not found:\n{exc}")
        except Exception as exc:
            logger.exception("Unexpected error during analysis")
            self.error.emit(f"Unexpected error:\n{exc}")

# ---------------------------------------------------------------------------
# Patch the GUI class with backend wiring
# ---------------------------------------------------------------------------

class CodeRiskAnalyzerApp(CodeRiskAnalyzerGUI):
    """Extends the base GUI class to wire up the real backend."""

    def __init__(self):
        super().__init__()
        self.selected_file = None
        self._worker = None

        # Replace combo items with the correct backend tools
        self.tool_combo.clear()
        self.tool_combo.addItems(list(TOOL_MAP.keys()))

        # Add a progress bar below the analyze button
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        self.Layout.insertWidget(
            self.Layout.indexOf(self.analyze_button) + 1,
            self.progress_bar
        )

        # Set monospace font on results panel
        self.results_text.setFont(QFont("Courier New", 10))
        self.results_text.setPlaceholderText(
            "Select a .c / .cpp file or directory, choose a tool, then click Analyze."
        )

    # ------------------------------------------------------------------
    # Override browse_files to restrict to C/C++ files
    # ------------------------------------------------------------------

    def browse_files(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select File or Directory", "",
            "C/C++ Files (*.c *.cpp);;All Files (*)"
        )
        if file_name:
            self.file_label.setText(f"Selected: {file_name}")
            self.selected_file = file_name

    # ------------------------------------------------------------------
    # Override analyze_code to call the real backend
    # ------------------------------------------------------------------

    def analyze_code(self):
        if not self.selected_file:
            QMessageBox.warning(self, "No Target", "Please select a file or directory first.")
            return

        display_name = self.tool_combo.currentText()
        tool_id = TOOL_MAP.get(display_name)
        if not tool_id:
            QMessageBox.warning(self, "Unknown Tool", f"No backend mapping for '{display_name}'.")
            return

        self.analyze_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.results_text.setPlainText("Running analysis — please wait…")

        self._worker = AnalysisWorker(self.selected_file, [tool_id])
        self._worker.finished.connect(self._on_analysis_done)
        self._worker.error.connect(self._on_analysis_error)
        self._worker.start()

    # ------------------------------------------------------------------
    # Worker callbacks
    # ------------------------------------------------------------------

    def _on_analysis_done(self, result):
        self.analyze_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.results_text.setPlainText(self._format_result(result))

    def _on_analysis_error(self, message):
        self.analyze_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.results_text.setPlainText(f"[ERROR]\n{message}")
        QMessageBox.critical(self, "Analysis Failed", message)

    # ------------------------------------------------------------------
    # Result formatter (carried over from original main.py)
    # ------------------------------------------------------------------

    @staticmethod
    def _format_result(result: AnalysisResult) -> str:
        lines = []
        summary = result.summary

        lines.append("=" * 60)
        lines.append(" TOOL RAW OUTPUT")
        lines.append("=" * 60)

        for tr in result.tool_results:
            lines.append(f"\n[{tr.tool_id}]")
            if tr.error:
                lines.append(f"  ERROR: {tr.error}")
                continue
            if hasattr(tr, "raw_output") and tr.raw_output:
                lines.append(tr.raw_output[:2000])
            else:
                lines.append("  (no raw output stored)")

        lines.append(f"\nTarget  : {summary['target']}")
        lines.append(f"Tools   : {', '.join(summary['tools_run']) or 'none'}")
        if summary["tools_failed"]:
            lines.append(f"Failed  : {', '.join(summary['tools_failed'])}")
        lines.append(f"Findings: {summary['total_findings']}")

        if summary["by_severity"]:
            lines.append("\nSeverity breakdown:")
            for sev, count in sorted(summary["by_severity"].items()):
                lines.append(f"  {sev:<12} {count}")

        lines.append("\nPer-tool count:")
        for tool_id, count in summary["by_tool"].items():
            lines.append(f"  {tool_id:<16} {count}")

        findings = result.all_findings
        if not findings:
            lines.append("\nNo findings — the target looks clean!")
            return "\n".join(lines)

        lines.append("\n" + "-" * 60)
        lines.append("  Findings")
        lines.append("-" * 60)

        for i, vuln in enumerate(findings, start=1):
            severity = getattr(vuln, "severity", "UNKNOWN")
            tool     = getattr(vuln, "tool", "?")
            lines.append(f"\n[{i}] {str(severity).upper()}  —  {tool}")

            file_ = getattr(vuln, "file", None) or getattr(vuln, "location", "n/a")
            line_ = getattr(vuln, "line", None)
            desc  = getattr(vuln, "description", None) or getattr(vuln, "message", "")
            cwe   = getattr(vuln, "cwe", None)

            loc = str(file_)
            if line_:
                loc += f":{line_}"
            lines.append(f"  Location : {loc}")
            if desc:
                lines.append(f"  Detail   : {desc}")
            if cwe:
                lines.append(f"  CWE      : {cwe}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("CodeRisk Analyzer")
    window = CodeRiskAnalyzerApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()