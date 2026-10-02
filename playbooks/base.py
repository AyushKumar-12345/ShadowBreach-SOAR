from abc import ABC, abstractmethod
from typing import Dict, Any

class BasePlaybook(ABC):
    @abstractmethod
    def execute(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        pass