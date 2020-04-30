from abc import ABCMeta, abstractmethod
from typing import List, Callable, NamedTuple, Tuple


class Rule(NamedTuple):
    prowler_id: str
    rule_id: str
    title: str
    scored: bool
    level: int
    cis_benchmark: bool
    check_function: Callable[[], Tuple[bool, List[str]]]


class AbstractCheck(metaclass=ABCMeta):
    @abstractmethod
    def rules(self) -> List[Rule]:
        pass
