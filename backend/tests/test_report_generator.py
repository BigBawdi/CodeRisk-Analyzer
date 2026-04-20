"""
Test and example usage of the ReportGenerator class.
Demonstrates how to generate reports in JSON, CSV, and HTML formats.
"""

import sys
from pathlib import Path

# Add backend to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.normalization.vulnerability_schema import Vulnerability
from frontend.report_generating import ReportGenerator


def create_sample_vulnerabilities():
    """Create sample vulnerability data for testing."""
    vulnerabilities = [
        Vulnerability(
            tool="cppcheck",
            file="src/main.cpp",
            line=45,
            vulnerability_type="Buffer Overflow",
            severity="Critical",
            message="Buffer overflow in strcpy function",
            cwe="CWE-120",
            cvss=9.8,
        ),
        Vulnerability(
            tool="cppcheck",
            file="src/parser.cpp",
            line=120,
            vulnerability_type="SQL Injection",
            severity="High",
            message="Unvalidated user input in SQL query",
            cwe="CWE-89",
            cvss=8.9,
        ),
        Vulnerability(
            tool="cppcheck",
            file="src/config.cpp",
            line=78,
            vulnerability_type="Hardcoded Password",
            severity="High",
            message="Hardcoded credential found",
            cwe="CWE-798",
            cvss=7.5,
        ),
        Vulnerability(
            tool="cppcheck",
            file="src/utils.cpp",
            line=156,
            vulnerability_type="Null Pointer Dereference",
            severity="Medium",
            message="Potential null pointer dereference",
            cwe="CWE-476",
            cvss=6.5,
        ),
        Vulnerability(
            tool="cppcheck",
            file="src/logger.cpp",
            line=89,
            vulnerability_type="Use After Free",
            severity="High",
            message="Use of freed memory",
            cwe="CWE-416",
            cvss=8.1,
        ),
        Vulnerability(
            tool="cppcheck",
            file="src/main.cpp",
            line=200,
            vulnerability_type="Integer Overflow",
            severity="Medium",
            message="Integer overflow in calculation",
            cwe="CWE-190",
            cvss=6.0,
        ),
        Vulnerability(
            tool="cppcheck",
            file="src/parser.cpp",
            line=345,
            vulnerability_type="Resource Leak",
            severity="Low",
            message="File descriptor not closed",
            cwe="CWE-775",
            cvss=3.3,
        ),
    ]
    return vulnerabilities


def test_json_generation():
    """Test JSON report generation."""
    print("=" * 60)
    print("Testing JSON Report Generation")
    print("=" * 60)
    
    vulnerabilities = create_sample_vulnerabilities()
    generator = ReportGenerator(vulnerabilities, title="CodeRisk Security Scan")
    
    json_report = generator.generate_json(include_stats=True)
    print("\nJSON Report Preview (first 500 characters):")
    print(json_report[:500] + "...")
    print("\n✅ JSON generation successful")


def test_csv_generation():
    """Test CSV report generation."""
    print("\n" + "=" * 60)
    print("Testing CSV Report Generation")
    print("=" * 60)
    
    vulnerabilities = create_sample_vulnerabilities()
    generator = ReportGenerator(vulnerabilities, title="CodeRisk Security Scan")
    
    csv_report = generator.generate_csv()
    print("\nCSV Report Preview:")
    print(csv_report[:400] + "...")
    print("\n✅ CSV generation successful")


def test_html_generation():
    """Test HTML report generation."""
    print("\n" + "=" * 60)
    print("Testing HTML Report Generation")
    print("=" * 60)
    
    vulnerabilities = create_sample_vulnerabilities()
    generator = ReportGenerator(vulnerabilities, title="CodeRisk Security Scan")
    
    html_report = generator.generate_html(include_stats=True)
    print(f"\nHTML Report size: {len(html_report)} characters")
    print(f"Contains statistics section: {'statistics' in html_report.lower()}")
    print(f"Contains vulnerability table: {'<tbody>' in html_report}")
    print("\n✅ HTML generation successful")


def test_export_all():
    """Test exporting all formats."""
    print("\n" + "=" * 60)
    print("Testing Export All Formats")
    print("=" * 60)
    
    vulnerabilities = create_sample_vulnerabilities()
    generator = ReportGenerator(vulnerabilities, title="CodeRisk Security Scan")
    
    output_dir = "/tmp/coderisk_reports"
    results = generator.export_all(output_dir, base_filename="security_report")
    
    print(f"\nExported reports to: {output_dir}")
    for fmt, filepath in results.items():
        print(f"  ✓ {fmt.upper()}: {filepath}")
    
    print("\n✅ Export all successful")


def test_summary():
    """Test summary generation."""
    print("\n" + "=" * 60)
    print("Testing Summary Generation")
    print("=" * 60)
    
    vulnerabilities = create_sample_vulnerabilities()
    generator = ReportGenerator(vulnerabilities, title="CodeRisk Security Scan")
    
    summary = generator.get_summary()
    print(summary)
    
    print("✅ Summary generation successful")


def test_empty_vulnerabilities():
    """Test with empty vulnerability list."""
    print("\n" + "=" * 60)
    print("Testing with Empty Vulnerabilities")
    print("=" * 60)
    
    generator = ReportGenerator([], title="Clean Scan Report")
    
    print("\nJSON Report (no vulnerabilities):")
    json_report = generator.generate_json()
    print(json_report[:300] + "...")
    
    print("\nSummary (no vulnerabilities):")
    print(generator.get_summary())
    
    print("\n✅ Empty test successful")


def test_statistics():
    """Test statistics calculation."""
    print("\n" + "=" * 60)
    print("Testing Statistics Calculation")
    print("=" * 60)
    
    vulnerabilities = create_sample_vulnerabilities()
    generator = ReportGenerator(vulnerabilities)
    
    stats = generator._calculate_statistics()
    print(f"\nTotal Vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"Files Affected: {stats['files_affected']}")
    print(f"\nSeverity Distribution:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity}: {count}")
    print(f"\nVulnerability Types:")
    for vuln_type, count in stats['by_type'].items():
        print(f"  {vuln_type}: {count}")
    print(f"\nTools Used:")
    for tool, count in stats['by_tool'].items():
        print(f"  {tool}: {count}")
    
    print("\n✅ Statistics calculation successful")


if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " CodeRisk-Analyzer Report Generator Tests ".center(58) + "║")
    print("╚" + "=" * 58 + "╝")
    
    try:
        test_json_generation()
        test_csv_generation()
        test_html_generation()
        test_statistics()
        test_summary()
        test_export_all()
        test_empty_vulnerabilities()
        
        print("\n" + "=" * 60)
        print("All Tests Passed! ✅")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
