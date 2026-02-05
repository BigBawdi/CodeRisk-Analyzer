from abc import ABC, abstractmethod
from typing import List, Dict, Any

from backend.normalization.vulnerability_schema import Vulnerability

class BaseParser(ABC):


    @abstractmethod
    def parse(self, raw_data: Any) -> List[Vulnerability]:
        """
      Parse raw tool output and return a list of normalized Vulnerability objects.
        """
        pass