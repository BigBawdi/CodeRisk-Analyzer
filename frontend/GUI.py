#GUI for the coderisk analyzer 
#Developed a PyQt6 interface with the file selection, tool selection, and the results displays
import sys
from PyQt6.QtWidgets import QApplication, QWidget,QVBoxLayout, QPushButton, QFileDialog, QLabel, QComboBox, QTextEdit
class CodeRiskAnalyzerGUI(QWidget):
    def __init__(self): 
        super().__init__()
        self.setWindowTitle("CodeRisk Analyzer")
        self.setGeometry(100, 100, 800, 600)
        self.Layout = QVBoxLayout()
        self.file_label = QLabel("Select a file or directory to analyze: ")
        self.file_button = QPushButton("Browse")
        self.file_button.clicked.connect(self.browse_files)
        self.tool_label = QLabel("Select a tool to analyze with: ")
        self.tool_combo = QComboBox()
        self.tool_combo.addItems(["Bandit", "Semgrep", "Safety"])
        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.clicked.connect(self.analyze_code)
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.Layout.addWidget(self.file_label)
        self.Layout.addWidget(self.file_button)
        self.Layout.addWidget(self.tool_Label)
        self.Layout.addWidget(self.tool_combo)
        self.Layout.addWidget(self.analyze_button)
        self.Layout.addWidget(self.results_text)
        self.setLayout(self.Layout)
    def browse_files(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File or Directory", "", "All Files (*);;Python Files (*,py)", options =options)
        if file_name:
            self.file_label.setText(f"Selected: {file_name}")
            self.selected_file = file_name
    def analyze_code(self):
        selected_tool = self.tool_combo.currentText()
        #Here we would call the backend analysis functions based on the selected tool and file
        #For demonstration, we will just display a placeholder result
        self.results_text.setText(f"Analyzing {self.selected_file} with {selected_tool}...\n\nResults:\n- Vulnerability 1: High severity\n- Vulnerability 2: Medium severity\n- Vulnerability 3: Low severity")
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CodeRiskAnalyzerGUI()
    window.show()
    sys.exit(app.exec())
    