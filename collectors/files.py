# File Collector - Computes SHA256 hashes of critical files.
# Maps to ISO 27002:2022 Control 8.9.

from typing import Any
from .base import Collector


class FileCollector(Collector):
    name = "files"
    description = "Critical file integrity verification"

    def __init__(self, file_paths: list[str] | None = None):
        self.file_paths = file_paths or []

    def get_command(self) -> str:
        if not self.file_paths:
            return "echo 'NO_FILES_SPECIFIED'"
        
        paths = " ".join(f'"{p}"' for p in self.file_paths)
        return f"sha256sum {paths} 2>&1"

    def parse_output(self, raw_output: str) -> dict[str, Any]:
        files = []
        
        for line in raw_output.strip().split("\n"):
            if not line or line == "NO_FILES_SPECIFIED":
                continue
                
            if "No such file" in line or "cannot read" in line:
                path = line.split(":")[-1].strip() if ":" in line else line
                for p in self.file_paths:
                    if p in line:
                        path = p
                        break
                files.append({
                    "path": path,
                    "sha256": None,
                    "exists": False,
                    "error": line
                })
                continue
            
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                hash_val, path = parts
                files.append({
                    "path": path.strip(),
                    "sha256": hash_val,
                    "exists": True
                })

        return {"files": files}

    def compare(
        self,
        actual: dict[str, Any],
        expected: dict[str, Any]
    ) -> dict[str, Any]:

        expected_files = {f["path"]: f.get("sha256") for f in expected}
        
        actual_files = {
            f["path"]: f 
            for f in actual.get("files", [])
        }
        
        matches = []
        mismatches = []
        missing = []
        
        for path, expected_hash in expected_files.items():
            actual_file = actual_files.get(path)
            
            if actual_file is None or not actual_file.get("exists"):
                missing.append({
                    "path": path,
                    "expected": expected_hash,
                    "actual": None,
                    "status": "MISSING"
                })
            elif expected_hash is None:
                matches.append({
                    "path": path,
                    "expected": None,
                    "actual": actual_file.get("sha256"),
                    "status": "CAPTURED"
                })
            elif actual_file.get("sha256") == expected_hash:
                matches.append({
                    "path": path,
                    "expected": expected_hash,
                    "actual": actual_file.get("sha256"),
                    "status": "MATCH"
                })
            else:
                mismatches.append({
                    "path": path,
                    "expected": expected_hash,
                    "actual": actual_file.get("sha256"),
                    "status": "DRIFT"
                })
        
        passed = len(mismatches) == 0 and len(missing) == 0

        return {
            "passed": passed,
            "matches": matches,
            "mismatches": mismatches,
            "missing": missing,
            "details": actual.get("files", [])
        }