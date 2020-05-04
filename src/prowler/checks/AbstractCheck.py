import inspect
from abc import ABCMeta, abstractmethod
from typing import List, Callable, NamedTuple

CheckFunction = Callable[[], None]


class Rule(NamedTuple):
    prowler_id: str
    rule_id: str
    title: str
    scored: bool
    level: int
    cis_benchmark: bool
    check_function: CheckFunction


class AbstractCheck(metaclass=ABCMeta):
    def checks_file(self) -> str:
        a = inspect.getfile(self.__class__).rsplit('.', 1)
        assert a[1] == 'py'
        return a[0] + '.yml'

    @abstractmethod
    def rules(self) -> List[Rule]:
        pass
