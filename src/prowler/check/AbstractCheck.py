from abc import ABCMeta, abstractmethod
from typing import List, Callable, Tuple, NamedTuple

CheckFunction = Callable[[], List[str]]
# rule id (compatible with prowler), short name, title, scored, level, check function
Rule = Tuple[str, str, str, bool, int, CheckFunction]


class AbstractCheck(metaclass=ABCMeta):
    @abstractmethod
    def rules(self) -> List[Rule]:
        pass
