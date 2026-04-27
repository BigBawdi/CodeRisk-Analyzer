"""
GUI.py — Base GUI class for the CodeRisk Analyzer application.
Contains only UI layout and widget definitions.
Backend wiring is handled in main.py via CodeRiskAnalyzerApp.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QTextEdit, QFrame,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


class CodeRiskAnalyzerGUI(QMainWindow):
    """
    Base GUI class — UI elements only.
    Subclass this in main.py to wire up the backend.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CodeRisk Analyzer")
        self.setMinimumSize(800, 600)
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Top-level vertical layout — stored as self.Layout so subclasses
        # can insert widgets (e.g. a progress bar) by index.
        self.Layout = QVBoxLayout(central_widget)
        self.Layout.setContentsMargins(16, 16, 16, 16)
        self.Layout.setSpacing(10)

        # -- Title label --------------------------------------------------
        title_label = QLabel("CodeRisk Analyzer")
        title_label.setFont(QFont("Courier New", 16, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.Layout.addWidget(title_label)

        # -- Divider ------------------------------------------------------
        self.Layout.addWidget(self._make_divider())

        # -- File selection row -------------------------------------------
        file_row = QHBoxLayout()

        self.file_label = QLabel("No file selected")
        self.file_label.setWordWrap(True)

        self.browse_button = QPushButton("Browse…")
        self.browse_button.setFixedWidth(100)
        self.browse_button.clicked.connect(self.browse_files)

        file_row.addWidget(self.file_label, stretch=1)
        file_row.addWidget(self.browse_button)
        self.Layout.addLayout(file_row)

        # -- Tool selection row -------------------------------------------
        tool_row = QHBoxLayout()

        tool_label = QLabel("Tool:")
        tool_label.setFixedWidth(40)

        self.tool_combo = QComboBox()
        self.tool_combo.addItems(["Cppcheck", "Flawfinder", "GCC Analyzer", "Coverity"])

        tool_row.addWidget(tool_label)
        tool_row.addWidget(self.tool_combo, stretch=1)
        self.Layout.addLayout(tool_row)

        # -- Analyze button -----------------------------------------------
        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.setFixedHeight(36)
        self.analyze_button.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
        self.analyze_button.clicked.connect(self.analyze_code)
        self.Layout.addWidget(self.analyze_button)

        # -- Divider ------------------------------------------------------
        self.Layout.addWidget(self._make_divider())

        # -- Results panel ------------------------------------------------
        results_label = QLabel("Results")
        results_label.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
        self.Layout.addWidget(results_label)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Courier New", 10))
        self.results_text.setPlaceholderText(
            "Select a .c / .cpp file or directory, choose a tool, then click Analyze."
        )
        self.Layout.addWidget(self.results_text, stretch=1)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_divider() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        return line

    # ------------------------------------------------------------------
    # Stubs — override in subclass
    # ------------------------------------------------------------------

    def browse_files(self):
        """Override in subclass to implement file selection."""
        raise NotImplementedError

    def analyze_code(self):
        """Override in subclass to implement analysis."""
        raise NotImplementedError