from .base import Collector
from .ports import PortCollector
from .users import UserCollector
from .files import FileCollector
from .processes import ProcessCollector

__all__ = [
    "Collector",
    "PortCollector",
    "UserCollector",
    "FileCollector",
    "ProcessCollector",
]

COLLECTORS = {
    "ports": PortCollector,
    "users": UserCollector,
    "files": FileCollector,
    "processes": ProcessCollector,
}