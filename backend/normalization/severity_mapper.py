def map_severity(raw_severity: str) -> str:
    if not raw_severity:
        return "Medium"

    raw = raw_severity.lower()

    if raw in {"critical", "high", "error"}:
        return "High"
    if raw in {"warning", "medium"}:
        return "Medium"
    if raw in {"low", "info", "style"}:
        return "Low"

    return "Medium"
