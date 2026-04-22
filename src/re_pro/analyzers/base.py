from __future__ import annotations

from abc import ABC, abstractmethod


class Analyzer(ABC):
    name = "Analyzer"

    @abstractmethod
    def analyze(self, context, report) -> None:
        raise NotImplementedError
