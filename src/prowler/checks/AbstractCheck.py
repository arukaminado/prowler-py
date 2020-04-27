from abc import ABCMeta, abstractmethod
from typing import List, Callable, NamedTuple


class Rule(NamedTuple):
    prowler_id: str
    rule_id: str
    title: str
    scored: bool
    level: int
    check_function: Callable[[], List[str]]


class AbstractCheck(metaclass=ABCMeta):
    @abstractmethod
    def rules(self) -> List[Rule]:
        pass
