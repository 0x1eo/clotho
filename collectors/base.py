# Abstract base collector for Clotho

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CollectorResult:
    collector_type: str
    node: str
    raw_output: str
    parsed_data: dict[str, Any]
    command: str
    success: bool
    error: str | None = None
    timestamp: str = field(default="")

    def __post_init__(self):
        if not self.timestamp:
            from datetime import datetime, timezone
            self.timestamp = datetime.now(timezone.utc).isoformat()


class Collector(ABC):

    name: str = "base"
    description: str = "Base collector"

    @abstractmethod
    def get_command(self) -> str:
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> dict[str, Any]:
        pass

    @abstractmethod
    def compare(
        self,
        actual: dict[str, Any],
        expected: dict[str, Any]
    ) -> dict[str, Any]:
        pass

    def execute(self, executor, node: str) -> CollectorResult:
        command = self.get_command()
        try:
            raw_output = executor.run(command)
            parsed = self.parse_output(raw_output)
            return CollectorResult(
                collector_type=self.name,
                node=node,
                raw_output=raw_output,
                parsed_data=parsed,
                command=command,
                success=True
            )
        except Exception as e:
            return CollectorResult(
                collector_type=self.name,
                node=node,
                raw_output="",
                parsed_data={},
                command=command,
                success=False,
                error=str(e)
            )