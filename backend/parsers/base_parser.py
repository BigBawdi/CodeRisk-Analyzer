from abc import ABC, abstractmethod
from typing import Any, List, Dict
from backend.normalization.vulnerability_schema import Vulnerability


class BaseParser(ABC):
    """
    Abstract parser.  Subclass this for every static-analysis tool.

    Class attributes
    ----------------
    tool_name : str
        Machine-readable name of the tool this parser handles.
        Used in log messages and as the `tool` field on every
        Vulnerability this parser produces.  Must be overridden.
    """

    # --- Subclasses MUST override this ---
    tool_name: str = "unknown"

    # ------------------------------------------------------------------
    # Abstract interface — the one method every subclass must implement
    # ------------------------------------------------------------------

    @abstractmethod
    def parse(self, raw_data: Any) -> List[Vulnerability]:
        """
        Parse raw tool output and return normalized Vulnerability objects.

        Parameters
        ----------
        raw_data:
            Whatever the tool runner produces — an XML file path (str),
            a JSON string, a list of dicts, etc.  Each subclass documents
            exactly what type it expects.

        Returns
        -------
        List[Vulnerability]
            Every item must have at minimum: tool, severity, message.
            file and line may be None for tools that don't report them.

        Raises
        ------
        Subclasses may raise ValueError or IOError for unrecoverable
        input problems.  The base class's safe_parse() will catch these.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Helpers available to every subclass (and to the service layer)
    # ------------------------------------------------------------------

    def safe_parse(self, raw_data: Any) -> List[Vulnerability]:
        """
        Exception-safe wrapper around parse().

        The pipeline calls this instead of parse() directly so that a
        broken parser output never takes down an entire analysis run.
        Any exception is logged and an empty list is returned.

        Returns
        -------
        List[Vulnerability]  (empty on failure)
        """
        try:
            results = self.parse(raw_data)
            return self.validate(results)
        except FileNotFoundError as exc:
            print(f"[{self.tool_name}] Input file not found: {exc}")
        except ValueError as exc:
            print(f"[{self.tool_name}] Parse error: {exc}")
        except Exception as exc:
            print(f"[{self.tool_name}] Unexpected error during parsing: {exc}")
        return []

    def validate(self, findings: List[Vulnerability]) -> List[Vulnerability]:
        """
        Drop any findings that are missing the fields every downstream
        component depends on.

        Required: tool, severity, message.
        A finding missing any of these is silently dropped and counted.

        Returns
        -------
        List[Vulnerability]  (only valid findings)
        """
        valid = []
        dropped = 0
        for v in findings:
            if v.tool and v.severity and v.message:
                valid.append(v)
            else:
                dropped += 1

        if dropped:
            print(
                f"[{self.tool_name}] Validation dropped {dropped} incomplete "
                f"finding(s) (missing tool / severity / message)."
            )
        return valid

    def summary(self, findings: List[Vulnerability]) -> Dict[str, int]:
        """
        Return a severity → count breakdown for quick logging.

        Example
        -------
        >>> parser.summary(vulns)
        {'High': 3, 'Medium': 7, 'Low': 2}
        """
        counts: Dict[str, int] = {}
        for v in findings:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} tool='{self.tool_name}'>"