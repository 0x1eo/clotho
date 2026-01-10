# User Collector - Enumerates system users.
# Maps to ISO 27002:2022 Control 5.15.

from typing import Any

from .base import Collector


class UserCollector(Collector):
    name = "users"
    description = "System user account enumeration"

    def get_command(self) -> str:
        return (
            "cat /etc/passwd | "
            "awk -F: '$7 !~ /(nologin|false)$/ {print $1\":\"$3\":\"$7}'"
        )

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        users = []
        
        for line in raw_output.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                users.append({
                    "name": parts[0],
                    "uid": int(parts[1]),
                    "shell": parts[2]
                })

        return {"users": users}

    def compare(
        self,
        actual: dict[str, Any],
        expected: dict[str, Any]
    ) -> dict[str, Any]:
        allowed = set(expected.get("allowed", []))
        forbidden = set(expected.get("forbidden", []))
        
        actual_users = {u["name"] for u in actual.get("users", [])}
        
        forbidden_found = actual_users & forbidden
        unexpected = (actual_users - allowed) if allowed else set()
        unexpected -= forbidden  # Don't double-count forbidden
        allowed_found = actual_users & allowed
        
        passed = len(forbidden_found) == 0

        return {
            "passed": passed,
            "allowed_found": sorted(allowed_found),
            "forbidden_found": sorted(forbidden_found),
            "unexpected": sorted(unexpected),
            "missing": sorted(allowed - actual_users) if allowed else [],
            "details": actual.get("users", [])
        }