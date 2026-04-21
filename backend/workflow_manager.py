from backend.file_validator import validate_files
from backend.tool_runner import run_tool
from backend.parsers import get_parser


def run_analysis_workflow(files, selected_tool):
    validated_files = validate_files(files)
    file_paths = [str(path) for path in validated_files]

    raw_output_path = run_tool(selected_tool, file_paths)

    parser = get_parser(selected_tool)
    findings = parser.safe_parse(raw_output_path)

    return {
        "tool": selected_tool,
        "files": file_paths,
        "raw_output_path": raw_output_path,
        "findings": findings,
    }