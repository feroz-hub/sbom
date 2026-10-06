from abc import ABC, abstractmethod

from ..diff import apply


class RepairRule(ABC):
    error_codes: set[str] = set()

    def can_repair(self, document, error) -> bool:
        return bool(self.propose(document, error))

    @abstractmethod
    def propose(self, document, error): ...

    def apply(self, document, proposal):
        return apply(document, proposal)
