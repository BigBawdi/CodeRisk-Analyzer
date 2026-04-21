from backend.parsers.cppcheck_parser import CppcheckParser
from backend.parsers.flawfinder_parser import FlawfinderParser
from backend.parsers.gccCompiler_parser import GCCAnalyzerParser
from backend.parsers.coverity_parser import CoverityParser


def get_parser(tool_name: str):
    """
    Return the correct parser instance based on tool name.
    """
    tool_name = tool_name.lower()

    if tool_name == "cppcheck":
        return CppcheckParser()

    elif tool_name == "flawfinder":
        return FlawfinderParser()

    elif tool_name == "gcc_analyzer":
        return GCCAnalyzerParser()

    elif tool_name == "coverity":
        return CoverityParser()

    else:
        raise ValueError(f"Unsupported tool: {tool_name}")