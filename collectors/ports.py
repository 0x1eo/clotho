# Port Collector - Enumerates listening TCP/UDP ports.
# Maps to ISO 27002:2022 Control 8.20.

import re
from typing import Any

from .base import Collector


class PortCollector(Collector):
    name = "ports"
    description = "Listening TCP/UDP port enumeration"

    def get_command(self) -> str:
        return "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        ports = []
        
        # tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
        ss_pattern = re.compile(
            r'^(tcp|udp)\s+\S+\s+\d+\s+\d+\s+'
            r'([\d.*:]+):(\d+)\s+[\d.*:]+:\*\s*'
            r'(?:users:\(\("([^"]+)")?',
            re.MULTILINE
        )
        
        # tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
        netstat_pattern = re.compile(
            r'^(tcp|udp)\s+\d+\s+\d+\s+'
            r'([\d.]+):(\d+)\s+[\d.]+:\*\s+'
            r'LISTEN\s+\d+/(\S+)',
            re.MULTILINE
        )

        for match in ss_pattern.finditer(raw_output):
            proto, addr, port, process = match.groups()
            ports.append({
                "port": int(port),
                "proto": proto,
                "address": addr,
                "process": process or "unknown"
            })

        # Fallback
        if not ports:
            for match in netstat_pattern.finditer(raw_output):
                proto, addr, port, process = match.groups()
                ports.append({
                    "port": int(port),
                    "proto": proto,
                    "address": addr,
                    "process": process
                })

        return {"listening": ports}

    def compare(
        self,
        actual: dict[str, Any],
        expected: dict[str, Any]
    ) -> dict[str, Any]:
        allowed = set(expected.get("allowed", []))
        forbidden = set(expected.get("forbidden", []))
        
        actual_ports = {p["port"] for p in actual.get("listening", [])}
        
        forbidden_found = actual_ports & forbidden
        unexpected = actual_ports - allowed - forbidden
        allowed_found = actual_ports & allowed
        
        passed = len(forbidden_found) == 0 and len(unexpected) == 0

        return {
            "passed": passed,
            "allowed_found": sorted(allowed_found),
            "forbidden_found": sorted(forbidden_found),
            "unexpected": sorted(unexpected),
            "missing": sorted(allowed - actual_ports),
            "details": actual.get("listening", [])
        }