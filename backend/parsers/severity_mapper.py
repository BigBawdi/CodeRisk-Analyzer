from backend.normalization.vulnerability_severity import SeverityLevel

def map_severity(severity: str) -> SeverityLevel:
    mapping = {
        "style": SeverityLevel.LOW,
        "performance": SeverityLevel.LOW,
        "warning": SeverityLevel.MEDIUM,
        "error": SeverityLevel.HIGH,
        "critical": SeverityLevel.CRITICAL,
    }

    return mapping.get(severity.lower(), SeverityLevel.UNDEFINED)