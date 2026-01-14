#!/usr/bin/env python3
"""
Automated compliance engine that bridges Linux system state
and ISO 27002:2022 documentation.

Usage:
    python clotho.py --baseline baseline.yaml --output report.pdf
    python clotho.py --baseline baseline.yaml --capture  # Capture baseline hashes
"""

import argparse
import gzip
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader

try:
    import paramiko
except ImportError:
    paramiko = None  # Allow dry-run without paramiko

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from collectors import COLLECTORS, FileCollector
from collectors.base import CollectorResult


@dataclass
class Finding:
    control_id: str
    control_title: str
    collector_type: str
    node: str
    passed: bool
    evidence: dict[str, Any]
    raw_output: str
    command: str
    timestamp: str = field(default="")

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class AuditReport:
    baseline_version: str
    standard: str
    organization: str
    generated_at: str
    nodes: list[str]
    findings: list[Finding]
    summary: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.summary:
            self._compute_summary()

    def _compute_summary(self):
        total = len(self.findings)
        passed = sum(1 for f in self.findings if f.passed)
        failed = total - passed

        by_control = {}
        for f in self.findings:
            if f.control_id not in by_control:
                by_control[f.control_id] = {"passed": 0, "failed": 0, "title": f.control_title}
            if f.passed:
                by_control[f.control_id]["passed"] += 1
            else:
                by_control[f.control_id]["failed"] += 1

        self.summary = {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": (passed / total * 100) if total > 0 else 0,
            "by_control": by_control,
            "entropy_detected": failed > 0
        }


class SSHExecutor:
    def __init__(self, host: str, port: int = 22, user: str = "root", timeout: int = 30, key_file: str | None = None):
        self.host = host
        self.port = port
        self.user = user
        self.timeout = timeout
        self.key_file = key_file
        self._client: paramiko.SSHClient | None = None

    def connect(self):
        if paramiko is None:
            raise RuntimeError("Paramiko not installed. Run: pip install paramiko")
        
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.user,
            "timeout": self.timeout,
            "allow_agent": True,
            "look_for_keys": True,
        }
        
        # If specific key file provided, use it
        if self.key_file:
            key_path = Path(self.key_file).expanduser()
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(str(key_path))
            except paramiko.ssh_exception.PasswordRequiredException:
                import getpass
                passphrase = getpass.getpass(f"Passphrase for {key_path}: ")
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(str(key_path), password=passphrase)
                except Exception:
                    # Try RSA if Ed25519 fails
                    pkey = paramiko.RSAKey.from_private_key_file(str(key_path), password=passphrase)
            connect_kwargs["pkey"] = pkey
            connect_kwargs["allow_agent"] = False
            connect_kwargs["look_for_keys"] = False
        
        try:
            self._client.connect(**connect_kwargs)
        except paramiko.ssh_exception.PasswordRequiredException:
            raise RuntimeError(
                f"Private key is encrypted and SSH agent not available.\n"
                f"Either:\n"
                f"  1. Start agent: eval (ssh-agent -c) && ssh-add ~/.ssh/id_ed25519\n"
                f"  2. Or use --key-file to specify your key directly"
            )
        except paramiko.ssh_exception.AuthenticationException as e:
            raise RuntimeError(
                f"SSH authentication failed for {self.user}@{self.host}:{self.port}\n"
                f"Ensure your SSH key is authorized on the remote host."
            ) from e

    def run(self, command: str) -> str:
        if self._client is None:
            self.connect()
        
        _, stdout, stderr = self._client.exec_command(command, timeout=self.timeout)
        output = stdout.read().decode("utf-8")
        errors = stderr.read().decode("utf-8")
        
        return output + errors if errors else output

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()




class LocalExecutor:
    def __init__(self):
        pass

    def run(self, command: str) -> str:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout + result.stderr

    def connect(self):
        pass

    def close(self):
        pass


class HistoryManager:
    def __init__(self, history_dir: str = "output/history"):
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
    
    def save_audit(self, audit_id: str, audit_data: dict[str, Any]):
        file_path = self.history_dir / f"{audit_id}.json.gz"
        with gzip.open(file_path, 'wt', encoding='utf-8') as f:
            json.dump(audit_data, f, indent=2)
    
    def load_audit(self, audit_id: str) -> dict[str, Any] | None:
        audit_id = audit_id.replace('.json.gz', '')
        file_path = self.history_dir / f"{audit_id}.json.gz"
        if not file_path.exists():
            return None
        with gzip.open(file_path, 'rt', encoding='utf-8') as f:
            return json.load(f)
    
    def list_audits(self) -> list[str]:
        return sorted([f.name.replace('.json.gz', '') for f in self.history_dir.glob("*.json.gz")])
    
    def get_latest_audit(self) -> str | None:
        audits = self.list_audits()
        return audits[-1] if audits else None
    
    def purge_old_audits(self, retention_days: int = 90):
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        for audit_file in self.history_dir.glob("*.json.gz"):
            try:
                audit_time = datetime.fromtimestamp(audit_file.stat().st_mtime, tz=timezone.utc)
                if audit_time < cutoff:
                    audit_file.unlink()
            except Exception:
                continue


class ComparisonEngine:
    def __init__(self):
        pass

    def compare(
        self,
        collector: Any,
        actual: dict[str, Any],
        expected: dict[str, Any]
    ) -> dict[str, Any]:
        return collector.compare(actual, expected)


class Reporter:
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = Path(template_dir)
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            block_start_string='\\BLOCK{',
            block_end_string='}',
            variable_start_string='\\VAR{',
            variable_end_string='}',
            comment_start_string='\\#{',
            comment_end_string='}',
            line_statement_prefix='%%',
            line_comment_prefix='%#',
            trim_blocks=True,
            autoescape=False
        )
        # Custom filters for LaTeX
        self.env.filters['latex_escape'] = self._latex_escape
        self.env.filters['status_color'] = self._status_color

    @staticmethod
    def _latex_escape(text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        replacements = {
            '&': r'\&',
            '%': r'\%',
            '$': r'\$',
            '#': r'\#',
            '_': r'\_',
            '{': r'\{',
            '}': r'\}',
            '~': r'\textasciitilde{}',
            '^': r'\textasciicircum{}',
            '\\': r'\textbackslash{}',
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    @staticmethod
    def _status_color(passed: bool) -> str:
        return "ForestGreen" if passed else "BrickRed"

    def render(self, report: AuditReport, output_path: str) -> str:
        template = self.env.get_template("report_template.tex.j2")
        
        rendered = template.render(
            report=report,
            findings=report.findings,
            summary=report.summary,
            generated_at=report.generated_at,
            organization=report.organization,
            standard=report.standard
        )
        
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
        
        return str(output)
    
    def render_html(self, report: AuditReport, output_path: str) -> str:
        html_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
        template = html_env.get_template("report_template.html.j2")
        
        rendered = template.render(
            report=report,
            findings=report.findings,
            summary=report.summary,
            generated_at=report.generated_at,
            organization=report.organization,
            standard=report.standard
        )
        
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
        
        return str(output)

    def compile_pdf(self, tex_path: str) -> str | None:
        tex_path = Path(tex_path)
        
        try:
            result = subprocess.run(
                ["pdflatex", "-interaction=nonstopmode", "-output-directory", 
                 str(tex_path.parent), str(tex_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            pdf_path = tex_path.with_suffix(".pdf")
            if pdf_path.exists():
                return str(pdf_path)
            else:
                print(f"PDF compilation failed:\n{result.stdout}\n{result.stderr}")
                return None
                
        except FileNotFoundError:
            print("pdflatex not found. Install texlive to compile PDFs.")
            return None
        except subprocess.TimeoutExpired:
            print("LaTeX compilation timed out.")
            return None


class Weaver:
    def __init__(self, baseline_path: str, key_file: str | None = None, show_diffs: bool = False, 
                 history_dir: str = "output/history"):
        self.baseline_path = Path(baseline_path)
        self.baseline = self._load_baseline()
        self.comparison_engine = ComparisonEngine()
        self.reporter = Reporter()
        self.findings: list[Finding] = []
        self.key_file = key_file
        self.show_diffs = show_diffs
        self.history_manager = HistoryManager(history_dir)
        self.baseline_cache_dir = Path("baseline_cache")
        self.baseline_cache_dir.mkdir(exist_ok=True)


    def _load_baseline(self) -> dict[str, Any]:
        with open(self.baseline_path) as f:
            baseline = yaml.safe_load(f)
        
        required = ["meta", "nodes", "controls"]
        for key in required:
            if key not in baseline:
                raise ValueError(f"Baseline missing required key: {key}")
        
        return baseline
    
    def dry_run(self, nodes: list[str] | None = None, 
                control_ids: list[str] | None = None,
                exclude_control_ids: list[str] | None = None):
        if nodes is None:
            nodes = list(self.baseline["nodes"].keys())
        
        controls_to_check = self._filter_controls(control_ids, exclude_control_ids)
        
        print("=" * 70)
        print("DRY RUN - Planned Audit Plan")
        print("=" * 70)
        print(f"\nBaseline: {self.baseline_path}")
        print(f"Organization: {self.baseline['meta'].get('organization', 'Unknown')}")
        print(f"Standard: {self.baseline['meta'].get('standard', 'ISO 27002:2022')}")
        
        print(f"\nNodes to audit ({len(nodes)}):")
        for node in nodes:
            node_config = self.baseline["nodes"].get(node)
            if node_config:
                print(f"  - {node} ({node_config.get('host')}:{node_config.get('port', 22)})")
        
        print(f"\nControls to check ({len(controls_to_check)}):")
        total_collectors = 0
        for control_id, control in controls_to_check.items():
            collectors = control.get("collectors", {})
            print(f"\n  [{control_id}] {control.get('title', 'Unknown')}")
            for collector_type in collectors.keys():
                print(f"      - {collector_type} collector")
                total_collectors += 1
        
        print(f"\n{'='*70}")
        print(f"Total: {len(nodes)} node(s) x {len(controls_to_check)} control(s) = {total_collectors} collector execution(s)")
        print(f"{'='*70}")
    
    def _filter_controls(self, control_ids: list[str] | None = None, 
                          exclude_control_ids: list[str] | None = None) -> dict[str, Any]:
        controls = self.baseline["controls"]
        
        if control_ids:
            filtered = {}
            for ctrl_id in control_ids:
                if ":" in ctrl_id:
                    prefix = ctrl_id.split(":")[0]
                    for cid, control in controls.items():
                        if cid.startswith(prefix):
                            filtered[cid] = control
                else:
                    if ctrl_id in controls:
                        filtered[ctrl_id] = controls[ctrl_id]
            controls = filtered
        
        if exclude_control_ids:
            controls = {k: v for k, v in controls.items() if k not in exclude_control_ids}
        
        return controls

    def get_executor(self, node_name: str, local: bool = False) -> SSHExecutor | LocalExecutor:
        if local:
            return LocalExecutor()
        
        node_config = self.baseline["nodes"].get(node_name)
        if not node_config:
            raise ValueError(f"Node not found in baseline: {node_name}")
        
        return SSHExecutor(
            host=node_config["host"],
            port=node_config.get("port", 22),
            user=node_config.get("user", "root"),
            timeout=self.baseline.get("audit", {}).get("timeout_seconds", 30),
            key_file=self.key_file
        )

    def collect_node(self, node_name: str, local: bool = False, 
                     controls_to_check: dict[str, Any] | None = None) -> list[CollectorResult]:
        results = []
        executor = self.get_executor(node_name, local)
        
        if controls_to_check is None:
            controls_to_check = self.baseline["controls"]
        
        try:
            executor.connect()
            
            control_items = list(controls_to_check.items())
            
            if tqdm:
                control_iterator = tqdm(control_items, desc=f"  {node_name}", leave=False)
            else:
                control_iterator = control_items
            
            for control_id, control in control_items:
                collectors_config = control.get("collectors", {})
                
                for collector_type, config in collectors_config.items():
                    if collector_type not in COLLECTORS:
                        if not tqdm:
                            print(f"  [!] Unknown collector type: {collector_type}")
                        continue
                    
                    if collector_type == "files":
                        file_paths = [f["path"] for f in config] if isinstance(config, list) else []
                        collector = FileCollector(file_paths)
                    else:
                        collector = COLLECTORS[collector_type]()
                    
                    if not tqdm:
                        print(f"  [{control_id}] Running {collector_type} collector...")
                    
                    result = collector.execute(executor, node_name)
                    result.control_id = control_id  # Attach control context
                    
                    if self.show_diffs and collector_type == "files" and result.success:
                        result.parsed_data = self._add_file_diffs(result.parsed_data, config, executor, node_name)
                    
                    results.append((control_id, control, collector, result, config))
        
        finally:
            executor.close()
        
        return results
    
    def _add_file_diffs(self, parsed_data: dict[str, Any], config: Any, executor: Any, node_name: str) -> dict[str, Any]:
        baseline_cache_key = f"{self.baseline_path.name}_{node_name}"
        cache_file = self.baseline_cache_dir / f"{baseline_cache_key}.json"
        
        baseline_files = {}
        if cache_file.exists():
            with open(cache_file) as f:
                baseline_files = json.load(f)
        
        for file_info in parsed_data.get("files", []):
            path = file_info["path"]
            
            if not file_info.get("exists"):
                continue
            
            for file_config in config if isinstance(config, list) else [config]:
                if file_config.get("path") == path and file_config.get("sha256"):
                    expected_hash = file_config["sha256"]
                    actual_hash = file_info.get("sha256")
                    
                    if expected_hash and actual_hash != expected_hash:
                        if path in baseline_files:
                            baseline_content = baseline_files[path]
                            actual_content = executor.run(f"cat {shlex.quote(path)}")
                            
                            import difflib
                            diff = list(difflib.unified_diff(
                                baseline_content.splitlines(keepends=True),
                                actual_content.splitlines(keepends=True),
                                fromfile=f"{path} (baseline)",
                                tofile=f"{path} (current)"
                            ))
                            file_info["diff"] = "".join(diff)
                        
                        baseline_files[path] = executor.run(f"cat {shlex.quote(path)}")
        
        if baseline_files:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_file, 'w') as f:
                json.dump(baseline_files, f, indent=2)
        
        return parsed_data

    def analyze(self, collection_results: list) -> list[Finding]:
        findings = []
        
        for control_id, control, collector, result, config in collection_results:
            if not result.success:
                finding = Finding(
                    control_id=control_id,
                    control_title=control["title"],
                    collector_type=collector.name,
                    node=result.node,
                    passed=False,
                    evidence={"error": result.error},
                    raw_output=result.raw_output,
                    command=result.command
                )
            else:
                comparison = self.comparison_engine.compare(
                    collector,
                    result.parsed_data,
                    config
                )
                
                finding = Finding(
                    control_id=control_id,
                    control_title=control["title"],
                    collector_type=collector.name,
                    node=result.node,
                    passed=comparison["passed"],
                    evidence=comparison,
                    raw_output=result.raw_output,
                    command=result.command
                )
            
            findings.append(finding)
        
        return findings

    def audit(self, nodes: list[str] | None = None, local: bool = False,
              control_ids: list[str] | None = None,
              exclude_control_ids: list[str] | None = None) -> AuditReport:
        if nodes is None:
            nodes = list(self.baseline["nodes"].keys())
        
        controls_to_check = self._filter_controls(control_ids, exclude_control_ids)
        all_findings = []
        
        node_iterator = tqdm(nodes, desc="Auditing nodes") if tqdm else nodes
        
        for node in node_iterator:
            if not tqdm:
                print(f"\n[*] Auditing node: {node}")
            results = self.collect_node(node, local, controls_to_check)
            findings = self.analyze(results)
            all_findings.extend(findings)
        
        meta = self.baseline["meta"]
        report = AuditReport(
            baseline_version=meta.get("version", "1.0"),
            standard=meta.get("standard", "ISO 27002:2022"),
            organization=meta.get("organization", "Unknown"),
            generated_at=datetime.now(timezone.utc).isoformat(),
            nodes=nodes,
            findings=all_findings
        )
        
        self.findings = all_findings
        return report
    
    def compare(self, current_report: AuditReport, compare_with: str, 
                node: str | None = None) -> dict[str, Any]:
        prior_audit = self.history_manager.load_audit(compare_with)
        
        if not prior_audit:
            raise ValueError(f"Audit '{compare_with}' not found in history")
        
        prior_findings = prior_audit.get("findings", [])
        current_findings = current_report.findings
        
        if node:
            prior_findings = [f for f in prior_findings if f.get("node") == node]
            current_findings = [f for f in current_findings if f.node == node]
        
        current_key = lambda f: (f.control_id, f.collector_type, f.node)
        prior_key = lambda f: (f.get("control_id"), f.get("collector_type"), f.get("node"))
        
        current_map = {current_key(f): f for f in current_findings}
        prior_map = {prior_key(f): f for f in prior_findings}
        
        new_failures = []
        resolved_failures = []
        unchanged_failures = []
        new_passes = []
        regressions = []
        
        all_keys = set(current_map.keys()) | set(prior_map.keys())
        
        for key in all_keys:
            current = current_map.get(key)
            prior = prior_map.get(key)
            
            if current and prior:
                if not current.passed and prior.get("passed"):
                    new_failures.append(current)
                elif not current.passed and not prior.get("passed"):
                    unchanged_failures.append(current)
                elif current.passed and not prior.get("passed"):
                    resolved_failures.append(current)
                    new_passes.append(current)
            elif current and not prior:
                if not current.passed:
                    new_failures.append(current)
            elif prior and not current:
                if prior.get("passed"):
                    regressions.append(prior)
        
        return {
            "compared_with": compare_with,
            "compared_at": current_report.generated_at,
            "baseline_at": prior_audit.get("generated_at"),
            "node": node,
            "summary": {
                "new_failures": len(new_failures),
                "resolved_failures": len(resolved_failures),
                "unchanged_failures": len(unchanged_failures),
                "regressions": len(regressions)
            },
            "new_failures": new_failures,
            "resolved_failures": resolved_failures,
            "unchanged_failures": unchanged_failures,
            "regressions": regressions
        }
    
    def get_trends(self, days: int = 30) -> dict[str, Any]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        audits = []
        
        for audit_id in self.history_manager.list_audits():
            audit_data = self.history_manager.load_audit(audit_id)
            
            if not audit_data or not audit_data.get("generated_at"):
                continue
                
            audit_time = datetime.fromisoformat(audit_data.get("generated_at", ""))
            
            if audit_time >= cutoff:
                audits.append(audit_data)
        
        if not audits:
            return {"error": "No audits found in the specified time range"}
        
        trends = []
        for audit in sorted(audits, key=lambda x: x.get("generated_at", "")):
            summary = audit.get("summary", {})
            trends.append({
                "timestamp": audit.get("generated_at"),
                "audit_id": audit.get("audit_id", "unknown"),
                "total_checks": summary.get("total_checks", 0),
                "passed": summary.get("passed", 0),
                "failed": summary.get("failed", 0),
                "pass_rate": summary.get("pass_rate", 0)
            })
        
        failing_controls = {}
        for audit in audits:
            for finding in audit.get("findings", []):
                control_id = finding.get("control_id")
                if not finding.get("passed"):
                    failing_controls[control_id] = failing_controls.get(control_id, 0) + 1
        
        return {
            "period_days": days,
            "total_audits": len(audits),
            "trends": trends,
            "failing_controls": sorted(failing_controls.items(), key=lambda x: x[1], reverse=True)
        }

    def generate_report(self, report: AuditReport, output_dir: str = "output", 
                        formats: list[str] | None = None) -> dict[str, str]:
        if formats is None:
            formats = ["html", "pdf", "json"]
        
        # Always ensure json is included for history tracking
        if "json" not in formats:
            formats.append("json")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        audit_id = f"audit_{timestamp}"
        
        result = {"audit_id": audit_id}
        
        # Generate HTML (default)
        if "html" in formats:
            html_path = output_dir / f"audit_report_{timestamp}.html"
            self.reporter.render_html(report, str(html_path))
            print(f"[+] HTML report: {html_path}")
            result["html"] = str(html_path)
        
        # Generate LaTeX and compile PDF (default)
        if "pdf" in formats:
            tex_path = output_dir / f"audit_report_{timestamp}.tex"
            self.reporter.render(report, str(tex_path))
            print(f"[+] LaTeX report: {tex_path}")
            result["tex"] = str(tex_path)
            
            pdf_path = self.reporter.compile_pdf(str(tex_path))
            if pdf_path:
                print(f"[+] PDF report: {pdf_path}")
                result["pdf"] = str(pdf_path)
        
        # Save JSON for programmatic access and history
        if "json" in formats:
            json_path = output_dir / f"audit_report_{timestamp}.json"
            json_data = {
                "audit_id": audit_id,
                "baseline_version": report.baseline_version,
                "standard": report.standard,
                "organization": report.organization,
                "generated_at": report.generated_at,
                "nodes": report.nodes,
                "summary": report.summary,
                "findings": [
                    {
                        "control_id": f.control_id,
                        "control_title": f.control_title,
                        "collector_type": f.collector_type,
                        "node": f.node,
                        "passed": f.passed,
                        "evidence": f.evidence,
                        "command": f.command,
                        "timestamp": f.timestamp
                    }
                    for f in report.findings
                ]
            }
            json_path.write_text(json.dumps(json_data, indent=2))
            print(f"[+] JSON report: {json_path}")
            result["json"] = str(json_path)
            
            # Save to history
            self.history_manager.save_audit(audit_id, json_data)
            
            # Purge old audits
            retention_days = self.baseline.get("audit", {}).get("evidence_retention_days", 90)
            self.history_manager.purge_old_audits(retention_days)
        
        return result


def main():
    parser = argparse.ArgumentParser(
        description="Clotho: Evidence-as-Code Compliance Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full audit of all nodes
  python clotho.py --baseline baseline.yaml

  # Audit specific node
  python clotho.py --baseline baseline.yaml --node athena

  # Local dry-run (test collectors on this machine)
  python clotho.py --baseline baseline.yaml --local

  # Dry-run to see what will be checked
  python clotho.py --baseline baseline.yaml --dry-run

  # Run specific controls only
  python clotho.py --baseline baseline.yaml --control 8.20,5.15

  # Compare with previous audit
  python clotho.py --baseline baseline.yaml --compare-with previous

  # Show trends
  python clotho.py --trend --days 30
        """
    )
    
    parser.add_argument(
        "--baseline", "-b",
        default="baseline.yaml",
        help="Path to baseline YAML (default: baseline.yaml)"
    )
    parser.add_argument(
        "--node", "-n",
        action="append",
        help="Node to audit (can specify multiple, default: all)"
    )
    parser.add_argument(
        "--output", "-o",
        default="output",
        help="Output directory (default: output)"
    )
    parser.add_argument(
        "--local", "-l",
        action="store_true",
        help="Run collectors locally (for testing)"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate baseline syntax"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned checks without execution"
    )
    parser.add_argument(
        "--control",
        action="append",
        help="Run specific controls (can specify multiple or ranges like 8:9)"
    )
    parser.add_argument(
        "--exclude-control",
        action="append",
        help="Exclude specific controls from audit"
    )
    parser.add_argument(
        "--show-diffs",
        action="store_true",
        help="Show file diffs when hash mismatches detected"
    )
    parser.add_argument(
        "--format",
        action="append",
        choices=["pdf", "html", "json"],
        help="Output formats (default: html,pdf)"
    )
    parser.add_argument(
        "--compare-with",
        help="Compare with previous audit (use 'previous' for latest)"
    )
    parser.add_argument(
        "--trend",
        action="store_true",
        help="Show compliance trends over time"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days for trend analysis (default: 30)"
    )
    parser.add_argument(
        "--key-file", "-k",
        default=None,
        help="SSH private key file (will prompt for passphrase if encrypted)"
    )
    parser.add_argument(
        "--history-dir",
        default="output/history",
        help="Directory for audit history (default: output/history)"
    )

    args = parser.parse_args()

    try:
        weaver = Weaver(
            args.baseline, 
            key_file=args.key_file, 
            show_diffs=args.show_diffs,
            history_dir=args.history_dir
        )
        print(f"[+] Loaded baseline: {args.baseline}")
        print(f"    Version: {weaver.baseline['meta'].get('version')}")
        print(f"    Standard: {weaver.baseline['meta'].get('standard')}")
        print(f"    Nodes: {list(weaver.baseline['nodes'].keys())}")
        
        if args.validate_only:
            print("\n[+] Baseline validation passed.")
            return 0
        
        if args.dry_run:
            weaver.dry_run(args.node, args.control, args.exclude_control)
            return 0
        
        if args.trend:
            trends = weaver.get_trends(args.days)
            if "error" in trends:
                print(f"[!] {trends['error']}")
                return 2
            
            print(f"\n{'='*60}")
            print(f"COMPLIANCE TRENDS (Last {args.days} days)")
            print(f"{'='*60}")
            print(f"Total Audits: {trends['total_audits']}")
            
            print(f"\n{'-'*60}")
            print("Pass Rate Over Time:")
            print(f"{'-'*60}")
            for trend in trends['trends']:
                print(f"{trend['timestamp'][:10]}: {trend['pass_rate']:.1f}% ({trend['passed']}/{trend['total_checks']})")
            
            print(f"\n{'-'*60}")
            print("Frequently Failing Controls:")
            print(f"{'-'*60}")
            for control_id, count in trends['failing_controls'][:5]:
                print(f"{control_id}: failed {count} time(s)")
            
            return 0
        
        report = weaver.audit(
            nodes=args.node, 
            local=args.local,
            control_ids=args.control,
            exclude_control_ids=args.exclude_control
        )
        
        print(f"\n{'='*60}")
        print("AUDIT SUMMARY")
        print(f"{'='*60}")
        print(f"Total Checks: {report.summary['total_checks']}")
        print(f"Passed:       {report.summary['passed']}")
        print(f"Failed:       {report.summary['failed']}")
        print(f"Pass Rate:    {report.summary['pass_rate']:.1f}%")
        
        if report.summary['entropy_detected']:
            print("\n[!] ENTROPY DETECTED - System has drifted from baseline")
        else:
            print("\n[+] ORDERED STATE CONFIRMED - No drift detected")
        
        result = weaver.generate_report(report, args.output, args.format)
        print(f"\nAudit ID: {result.get('audit_id', 'unknown')}")
        
        if args.compare_with:
            if args.compare_with == "previous":
                args.compare_with = weaver.history_manager.get_latest_audit()
                if not args.compare_with:
                    print("[!] No previous audit found for comparison")
                    return 2
                print(f"\n[*] Comparing with: {args.compare_with}")
            
            comparison = weaver.compare(report, args.compare_with, args.node[0] if args.node else None)
            
            print(f"\n{'='*60}")
            print(f"COMPARISON WITH {args.compare_with}")
            print(f"{'='*60}")
            summary = comparison['summary']
            print(f"New Failures:      {summary['new_failures']}")
            print(f"Resolved Failures: {summary['resolved_failures']}")
            print(f"Unchanged:        {summary['unchanged_failures']}")
            print(f"Regressions:      {summary['regressions']}")
            
            if summary['new_failures'] > 0:
                print(f"\n[!] New Failures:")
                for finding in comparison['new_failures']:
                    print(f"  - [{finding.control_id}] {finding.node}: {finding.collector_type}")
        
        return 1 if report.summary['failed'] > 0 else 0

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())