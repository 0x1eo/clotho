# Process Collector - Enumerates running processes.
# Maps to ISO 27002:2022 Control 8.21.

import re
from typing import Any

from .base import Collector


class ProcessCollector(Collector):
    name = "processes"
    description = "Running process enumeration"

    def get_command(self) -> str:
        return "ps aux --no-headers | awk '{print $11}' | xargs -I{} basename {} | sort -u"

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        processes = []
        
        for line in raw_output.strip().split("\n"):
            proc = line.strip()
            if proc and not proc.startswith("["):  # Skip kernel threads
                proc_name = re.sub(r'^.*/', '', proc)
                proc_name = re.sub(r':.*$', '', proc_name)
                if proc_name:
                    processes.append(proc_name)

        return {"processes": sorted(set(processes))}

    def compare(
        self,
        actual: dict[str, Any],
        expected: dict[str, Any]
    ) -> dict[str, Any]:
        allowed = set(expected.get("allowed", []))
        forbidden = set(expected.get("forbidden", []))
        
        actual_procs = set(actual.get("processes", []))
        
        forbidden_found = actual_procs & forbidden
        allowed_found = actual_procs & allowed
        
        passed = len(forbidden_found) == 0

        return {
            "passed": passed,
            "allowed_found": sorted(allowed_found),
            "forbidden_found": sorted(forbidden_found),
            "unexpected": [],  # Processes are more fluid; don't flag unexpected
            "missing": sorted(allowed - actual_procs) if allowed else [],
            "details": sorted(actual_procs)
        }