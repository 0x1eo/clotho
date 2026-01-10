#!/usr/bin/env python3
"""
Automated compliance engine that bridges Linux system state
and ISO 27002:2022 documentation.

Usage:
    python clotho.py --baseline baseline.yaml --output report.pdf
    python clotho.py --baseline baseline.yaml --capture  # Capture baseline hashes
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader

try:
    import paramiko
except ImportError:
    paramiko = None  # Allow dry-run without paramiko

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
    def __init__(self, baseline_path: str, key_file: str | None = None):
        self.baseline_path = Path(baseline_path)
        self.baseline = self._load_baseline()
        self.comparison_engine = ComparisonEngine()
        self.reporter = Reporter()
        self.findings: list[Finding] = []
        self.key_file = key_file


    def _load_baseline(self) -> dict[str, Any]:
        with open(self.baseline_path) as f:
            baseline = yaml.safe_load(f)
        
        required = ["meta", "nodes", "controls"]
        for key in required:
            if key not in baseline:
                raise ValueError(f"Baseline missing required key: {key}")
        
        return baseline

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

    def collect_node(self, node_name: str, local: bool = False) -> list[CollectorResult]:
        results = []
        executor = self.get_executor(node_name, local)
        
        try:
            executor.connect()
            
            for control_id, control in self.baseline["controls"].items():
                collectors_config = control.get("collectors", {})
                
                for collector_type, config in collectors_config.items():
                    if collector_type not in COLLECTORS:
                        print(f"  [!] Unknown collector type: {collector_type}")
                        continue
                    
                    if collector_type == "files":
                        file_paths = [f["path"] for f in config] if isinstance(config, list) else []
                        collector = FileCollector(file_paths)
                    else:
                        collector = COLLECTORS[collector_type]()
                    
                    print(f"  [{control_id}] Running {collector_type} collector...")
                    result = collector.execute(executor, node_name)
                    result.control_id = control_id  # Attach control context
                    results.append((control_id, control, collector, result, config))
        
        finally:
            executor.close()
        
        return results

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

    def audit(self, nodes: list[str] | None = None, local: bool = False) -> AuditReport:
        if nodes is None:
            nodes = list(self.baseline["nodes"].keys())
        
        all_findings = []
        
        for node in nodes:
            print(f"\n[*] Auditing node: {node}")
            results = self.collect_node(node, local)
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

    def generate_report(self, report: AuditReport, output_dir: str = "output") -> dict[str, str]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate LaTeX
        tex_path = output_dir / f"audit_report_{timestamp}.tex"
        self.reporter.render(report, str(tex_path))
        print(f"\n[+] LaTeX report: {tex_path}")
        
        # Also save JSON for programmatic access
        json_path = output_dir / f"audit_report_{timestamp}.json"
        json_data = {
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
        
        # Compile PDF
        pdf_path = self.reporter.compile_pdf(str(tex_path))
        if pdf_path:
            print(f"[+] PDF report: {pdf_path}")
        
        return {
            "tex": str(tex_path),
            "json": str(json_path),
            "pdf": pdf_path
        }


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

  # Just validate baseline syntax
  python clotho.py --baseline baseline.yaml --validate-only
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
        "--json-only",
        action="store_true",
        help="Skip PDF generation, output JSON only"
    )
    parser.add_argument(
        "--key-file", "-k",
        default=None,
        help="SSH private key file (will prompt for passphrase if encrypted)"
    )

    args = parser.parse_args()

    try:
        weaver = Weaver(args.baseline, key_file=args.key_file)
        print(f"[+] Loaded baseline: {args.baseline}")
        print(f"    Version: {weaver.baseline['meta'].get('version')}")
        print(f"    Standard: {weaver.baseline['meta'].get('standard')}")
        print(f"    Nodes: {list(weaver.baseline['nodes'].keys())}")
        
        if args.validate_only:
            print("\n[+] Baseline validation passed.")
            return 0
        
        report = weaver.audit(nodes=args.node, local=args.local)
        
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
        
        if not args.json_only:
            weaver.generate_report(report, args.output)
        
        return 1 if report.summary['failed'] > 0 else 0

    except Exception as e:
        print(f"[!] Error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())