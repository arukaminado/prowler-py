from abc import ABCMeta, abstractmethod
from typing import List


class AbstractCheck(metaclass=ABCMeta):
    @property
    @abstractmethod
    def id(self) -> str:
        pass

    @property
    @abstractmethod
    def title(self) -> str:
        pass

    @property
    @abstractmethod
    def scored(self) -> bool:
        pass

    @property
    @abstractmethod
    def level(self) -> int:
        pass

    @abstractmethod
    def check(self) -> List[str]:
        pass
