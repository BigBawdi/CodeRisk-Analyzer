def map_vulnerability_type(tool_id: str) -> str:
    if not tool_id:
        return "Unknown"

    tool_id = tool_id.lower()

    if "buffer" in tool_id:
        return "Buffer Overflow"
    if "null" in tool_id:
        return "Null Pointer Dereference"
    if "format" in tool_id:
        return "Format String"
    if "race" in tool_id:
        return "Race Condition"
    if "memory" in tool_id:
        return "Memory Management"

    return "Other"
