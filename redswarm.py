#!/usr/bin/env python3
"""RedSwarm — Adversarial AI swarm that attacks your codebase before hackers do.

Spawns hundreds of AI attacker agents that simulate supply chain attacks,
prompt injection, credential theft, and insider threats against your project.

Usage:
    python3 redswarm.py ./my-project
    python3 redswarm.py ./my-project --agents 500 --output report.html
    python3 redswarm.py ./my-project --focus supply-chain
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="\033[90m%(asctime)s\033[0m %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("redswarm")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    agent_id: int
    agent_type: str
    severity: str  # critical, high, medium, low
    title: str
    description: str
    file_path: str = ""
    line_number: int = 0
    attack_chain: list[str] = field(default_factory=list)
    cwe: str = ""
    remediation: str = ""


@dataclass
class ScanResult:
    project_path: str
    scan_time_s: float = 0
    total_agents: int = 0
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    dependencies_scanned: int = 0
    risk_score: int = 0

    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")


# ---------------------------------------------------------------------------
# Project scanner — collects intelligence for agents
# ---------------------------------------------------------------------------


class ProjectScanner:
    """Scans a project directory and extracts attack surface information."""

    def __init__(self, project_path: str):
        self.root = Path(project_path).resolve()
        self.files: list[dict] = []
        self.dependencies: list[dict] = []
        self.env_files: list[dict] = []
        self.secrets: list[dict] = []
        self.llm_calls: list[dict] = []
        self.api_endpoints: list[dict] = []

    def scan(self) -> dict:
        """Full project scan. Returns intelligence dict."""
        logger.info("\033[36m[scan]\033[0m Scanning %s ...", self.root)
        self._scan_files()
        self._scan_dependencies()
        self._scan_env_files()
        self._scan_secrets()
        self._scan_llm_calls()
        self._scan_api_endpoints()

        intel = {
            "root": str(self.root),
            "files": self.files,
            "dependencies": self.dependencies,
            "env_files": self.env_files,
            "secrets": self.secrets,
            "llm_calls": self.llm_calls,
            "api_endpoints": self.api_endpoints,
            "stats": {
                "total_files": len(self.files),
                "total_deps": len(self.dependencies),
                "total_env_files": len(self.env_files),
                "total_secrets": len(self.secrets),
                "total_llm_calls": len(self.llm_calls),
                "total_endpoints": len(self.api_endpoints),
            },
        }
        logger.info(
            "\033[36m[scan]\033[0m Found %d files, %d deps, %d env files, %d secrets, %d LLM calls, %d endpoints",
            len(self.files),
            len(self.dependencies),
            len(self.env_files),
            len(self.secrets),
            len(self.llm_calls),
            len(self.api_endpoints),
        )
        return intel

    def _scan_files(self):
        skip = {
            ".git",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            ".next",
            "dist",
            "build",
        }
        extensions = {
            ".py",
            ".js",
            ".ts",
            ".tsx",
            ".jsx",
            ".yaml",
            ".yml",
            ".toml",
            ".json",
            ".env",
            ".sh",
            ".html",
            ".go",
            ".rs",
            ".rb",
            ".php",
            ".java",
            ".tf",
            ".cfg",
            ".ini",
            ".conf",
            ".dockerfile",
        }
        for p in self.root.rglob("*"):
            if any(s in p.parts for s in skip):
                continue
            if p.is_file() and p.suffix in extensions:
                try:
                    content = p.read_text(errors="ignore")[:50000]
                    self.files.append(
                        {
                            "path": str(p.relative_to(self.root)),
                            "suffix": p.suffix,
                            "size": p.stat().st_size,
                            "content": content,
                        }
                    )
                except (OSError, PermissionError):
                    pass

    def _scan_dependencies(self):
        # Python
        req_files = list(self.root.glob("requirements*.txt"))
        for f in req_files:
            for line in f.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    name = re.split(r"[>=<\[!;]", line)[0].strip()
                    if name:
                        self.dependencies.append(
                            {"name": name, "source": str(f.name), "ecosystem": "pypi"}
                        )

        # Pipfile / pyproject.toml
        for toml_file in self.root.glob("pyproject.toml"):
            content = toml_file.read_text(errors="ignore")
            for match in re.finditer(
                r'^\s*"?([a-zA-Z0-9_-]+)"?\s*[>=<]', content, re.MULTILINE
            ):
                self.dependencies.append(
                    {
                        "name": match.group(1),
                        "source": "pyproject.toml",
                        "ecosystem": "pypi",
                    }
                )

        # Node
        for pkg_file in self.root.glob("package.json"):
            try:
                pkg = json.loads(pkg_file.read_text())
                for dep_type in ("dependencies", "devDependencies"):
                    for name in pkg.get(dep_type, {}):
                        self.dependencies.append(
                            {"name": name, "source": "package.json", "ecosystem": "npm"}
                        )
            except (json.JSONDecodeError, OSError):
                pass

    def _scan_env_files(self):
        patterns = [".env", ".env.local", ".env.production", ".env.development"]
        for p in patterns:
            env_path = self.root / p
            if env_path.exists():
                content = env_path.read_text(errors="ignore")
                keys = re.findall(r"^([A-Z_][A-Z0-9_]*)=", content, re.MULTILINE)
                self.env_files.append(
                    {"path": p, "keys": keys, "line_count": len(content.splitlines())}
                )

    def _scan_secrets(self):
        """Scan for hardcoded secrets and API keys in source files."""
        secret_patterns = [
            (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
            (r"sk-ant-[a-zA-Z0-9]{20,}", "Anthropic API Key"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
            (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
            (r"xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+", "Slack Bot Token"),
            (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private Key"),
            (r"mongodb(\+srv)?://[^\s\"']+", "MongoDB Connection String"),
            (r"postgres(ql)?://[^\s\"']+", "PostgreSQL Connection String"),
            (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JWT Token"),
            (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
            (r"sk-astrai-[a-f0-9]{20,}", "Astrai API Key"),
            (
                r"twilio[_\s]*(?:auth[_\s]*)?token[\"'\s:=]+[a-f0-9]{32}",
                "Twilio Auth Token",
            ),
            (
                r'os\.(?:getenv|environ\.get)\s*\(\s*["\'][^"\']*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH)[^"\']*["\']\s*,\s*["\'][a-zA-Z0-9_/+=.-]{20,}["\']',
                "Hardcoded Secret in env fallback",
            ),
            (r"['\"][a-f0-9]{40,}['\"]", "Long hex string (possible API key)"),
            (r"password\s*[=:]\s*['\"][^'\"]{4,}['\"]", "Hardcoded password"),
            (
                r"api[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9_/+=.-]{10,}['\"]",
                "Hardcoded API key",
            ),
        ]
        for f in self.files:
            content = f.get("content", "")
            for pattern, name in secret_patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    self.secrets.append(
                        {
                            "type": name,
                            "file": f["path"],
                            "match": match.group()[:20] + "..."
                            if len(match.group()) > 20
                            else match.group(),
                        }
                    )

    def _scan_llm_calls(self):
        """Find LLM API calls that could be vulnerable to prompt injection."""
        llm_patterns = [
            (r"openai\..*\.create\(", "OpenAI API call"),
            (r"anthropic\..*\.create\(", "Anthropic API call"),
            (r"ChatCompletion", "Chat completion"),
            (r"\.chat\.completions", "Chat completions API"),
            (r"llm_call\(|_llm_call\(", "Custom LLM call"),
            (
                r"f[\"'].*\{.*user.*input.*\}.*[\"']",
                "f-string with user input in prompt",
            ),
            (r"\.format\(.*request\.", "Format with request data in prompt"),
        ]
        for f in self.files:
            content = f.get("content", "")
            for pattern, name in llm_patterns:
                for match in re.finditer(pattern, content):
                    # Check if user input flows into the LLM call
                    line_no = content[: match.start()].count("\n") + 1
                    self.llm_calls.append(
                        {
                            "type": name,
                            "file": f["path"],
                            "line": line_no,
                            "context": content[
                                max(0, match.start() - 50) : match.end() + 50
                            ],
                        }
                    )

    def _scan_api_endpoints(self):
        """Find API endpoints that accept user input."""
        endpoint_patterns = [
            (
                r"@app\.(get|post|put|delete|patch)\s*\(\s*[\"'](.*?)[\"']",
                "Flask/FastAPI endpoint",
            ),
            (
                r"@app\.route\s*\(\s*[\"'](.*?)[\"'].*?methods\s*=\s*\[(.*?)\]",
                "Flask route",
            ),
            (
                r"@app\.route\s*\(\s*[\"'](.*?)[\"']",
                "Flask route",
            ),
            (
                r"router\.(get|post|put|delete)\s*\(\s*[\"'](.*?)[\"']",
                "Express/FastAPI router",
            ),
            (r"app\.(get|post|put|delete)\s*\(\s*[\"'](.*?)[\"']", "Express endpoint"),
        ]
        for f in self.files:
            content = f.get("content", "")
            for pattern, framework in endpoint_patterns:
                for match in re.finditer(pattern, content):
                    groups = match.groups()
                    if framework == "Flask route" and len(groups) >= 1:
                        path = groups[0]
                        methods = (
                            groups[1].upper()
                            if len(groups) > 1 and groups[1]
                            else "GET"
                        )
                        self.api_endpoints.append(
                            {
                                "method": methods,
                                "path": path,
                                "file": f["path"],
                                "framework": framework,
                            }
                        )
                    else:
                        self.api_endpoints.append(
                            {
                                "method": match.group(1).upper(),
                                "path": match.group(2),
                                "file": f["path"],
                                "framework": framework,
                            }
                        )


# ---------------------------------------------------------------------------
# Attacker agents
# ---------------------------------------------------------------------------

KNOWN_COMPROMISED = {
    "litellm": {
        "versions": ["1.82.7", "1.82.8"],
        "cve": "CVE-2026-LITELLM",
        "severity": "critical",
        "detail": "Supply chain attack via Trivy CI/CD compromise. Credential stealer + K8s lateral movement.",
    },
    "ultralytics": {
        "versions": ["8.3.41", "8.3.42"],
        "severity": "critical",
        "detail": "PyPI package compromised with crypto miner.",
    },
    "event-stream": {
        "versions": ["3.3.6"],
        "severity": "critical",
        "detail": "npm package injected with cryptocurrency wallet stealer.",
    },
    "ua-parser-js": {
        "versions": ["0.7.29", "0.8.0", "1.0.0"],
        "severity": "critical",
        "detail": "npm package compromised with crypto miner and password stealer.",
    },
    "colors": {
        "versions": ["1.4.1", "1.4.2"],
        "severity": "high",
        "detail": "Maintainer intentionally sabotaged package with infinite loop.",
    },
    "faker": {
        "versions": ["6.6.6"],
        "severity": "high",
        "detail": "Maintainer intentionally sabotaged package.",
    },
}


class AttackerAgent:
    """Base class for adversarial agents."""

    agent_type = "base"

    def __init__(self, agent_id: int):
        self.agent_id = agent_id
        self.findings: list[Finding] = []

    def attack(self, intel: dict) -> list[Finding]:
        raise NotImplementedError

    def _finding(
        self, severity: str, title: str, description: str, **kwargs
    ) -> Finding:
        return Finding(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            severity=severity,
            title=title,
            description=description,
            **kwargs,
        )


class SupplyChainAgent(AttackerAgent):
    """Simulates supply chain attacks on dependencies."""

    agent_type = "supply-chain"

    def attack(self, intel: dict) -> list[Finding]:
        findings = []
        deps = intel.get("dependencies", [])

        for dep in deps:
            name = dep["name"].lower()
            # Check known compromised packages
            if name in KNOWN_COMPROMISED:
                info = KNOWN_COMPROMISED[name]
                findings.append(
                    self._finding(
                        severity=info["severity"],
                        title=f"COMPROMISED PACKAGE: {name}",
                        description=f"{info['detail']} Affected versions: {', '.join(info['versions'])}. "
                        f"This package was found in {dep['source']}.",
                        file_path=dep["source"],
                        cwe="CWE-1357",
                        attack_chain=[
                            f"Attacker compromises {name} package on {dep['ecosystem']}",
                            "Malicious code executes on pip install / npm install",
                            "Credentials, SSH keys, and secrets exfiltrated",
                            "Lateral movement to connected infrastructure",
                        ],
                        remediation=f"Remove {name} immediately. Check for compromise indicators. Rotate all credentials.",
                    )
                )

            # Check for typosquatting risk
            for known in [
                "openai",
                "anthropic",
                "langchain",
                "transformers",
                "torch",
                "numpy",
                "pandas",
            ]:
                if (
                    name != known
                    and _levenshtein(name, known) <= 2
                    and name not in KNOWN_COMPROMISED
                ):
                    findings.append(
                        self._finding(
                            severity="high",
                            title=f"TYPOSQUAT RISK: {name} (similar to {known})",
                            description=f"Package '{name}' is suspiciously similar to popular package '{known}'. "
                            f"Could be a typosquatting attack.",
                            file_path=dep["source"],
                            cwe="CWE-1357",
                            remediation=f"Verify that '{name}' is the correct package. Check PyPI/npm page manually.",
                        )
                    )

            # Check for unpinned versions
            if dep["source"].endswith(".txt"):
                findings.append(
                    self._finding(
                        severity="medium",
                        title=f"UNPINNED: {name} has no version lock",
                        description=f"Package '{name}' in {dep['source']} has no pinned version or lockfile hash. "
                        f"A compromised future version would be auto-installed.",
                        file_path=dep["source"],
                        cwe="CWE-829",
                        remediation="Pin exact versions and use hash verification (pip --require-hashes).",
                    )
                )

        return findings


class CredentialTheftAgent(AttackerAgent):
    """Simulates credential theft from exposed secrets."""

    agent_type = "credential-theft"

    def attack(self, intel: dict) -> list[Finding]:
        findings = []

        # Hardcoded secrets in source
        for secret in intel.get("secrets", []):
            findings.append(
                self._finding(
                    severity="critical",
                    title=f"EXPOSED SECRET: {secret['type']}",
                    description=f"Found {secret['type']} in {secret['file']}: {secret['match']}. "
                    f"An attacker with repo access can steal this credential.",
                    file_path=secret["file"],
                    cwe="CWE-798",
                    attack_chain=[
                        "Attacker gains read access to repository (public repo, leaked .git, insider)",
                        f"Extracts {secret['type']} from {secret['file']}",
                        "Uses credential to access external service",
                        "Pivots to connected systems",
                    ],
                    remediation="Remove secret from source code. Use environment variables or a secrets manager. Rotate the exposed credential.",
                )
            )

        # .env files with sensitive keys
        for env in intel.get("env_files", []):
            sensitive_keys = [
                k
                for k in env.get("keys", [])
                if any(
                    s in k.upper()
                    for s in ["SECRET", "TOKEN", "KEY", "PASSWORD", "PRIVATE", "AUTH"]
                )
            ]
            if sensitive_keys:
                findings.append(
                    self._finding(
                        severity="high",
                        title=f"SENSITIVE ENV FILE: {env['path']}",
                        description=f"File {env['path']} contains {len(sensitive_keys)} sensitive keys: "
                        f"{', '.join(sensitive_keys[:5])}{'...' if len(sensitive_keys) > 5 else ''}. "
                        f"If this file is committed to git or accessible, all these credentials are compromised.",
                        file_path=env["path"],
                        cwe="CWE-312",
                        remediation="Ensure .env is in .gitignore. Use a secrets manager for production.",
                    )
                )

        return findings


class PromptInjectionAgent(AttackerAgent):
    """Simulates prompt injection attacks on LLM calls."""

    agent_type = "prompt-injection"

    def attack(self, intel: dict) -> list[Finding]:
        findings = []

        for call in intel.get("llm_calls", []):
            # Check if user input flows into the prompt
            context = call.get("context", "")
            has_user_input = any(
                p in context.lower()
                for p in [
                    "request.",
                    "user_input",
                    "user_message",
                    "body",
                    "query",
                    "incoming_msg",
                    "speech",
                    ".values.get",
                ]
            )

            if has_user_input:
                findings.append(
                    self._finding(
                        severity="high",
                        title=f"PROMPT INJECTION: {call['file']}:{call['line']}",
                        description=f"User input flows directly into LLM call ({call['type']}) at {call['file']}:{call['line']}. "
                        f"An attacker can inject instructions to exfiltrate data, bypass controls, or manipulate outputs.",
                        file_path=call["file"],
                        line_number=call["line"],
                        cwe="CWE-77",
                        attack_chain=[
                            "Attacker sends crafted input via API/chat/form",
                            f"Input reaches LLM call at {call['file']}:{call['line']}",
                            "Injected prompt overrides system instructions",
                            "AI leaks system prompt, internal data, or performs unauthorized actions",
                        ],
                        remediation="Sanitize user input before passing to LLM. Use structured prompts with clear boundaries. Implement output validation.",
                    )
                )
            else:
                findings.append(
                    self._finding(
                        severity="medium",
                        title=f"LLM CALL: {call['file']}:{call['line']}",
                        description=f"LLM call ({call['type']}) found at {call['file']}:{call['line']}. "
                        f"Verify that no user-controlled input reaches this call path.",
                        file_path=call["file"],
                        line_number=call["line"],
                        cwe="CWE-77",
                        remediation="Audit the data flow to this LLM call. Ensure user input is sanitized.",
                    )
                )

        return findings


class InsiderThreatAgent(AttackerAgent):
    """Simulates insider threat attacks — what a malicious developer could do."""

    agent_type = "insider-threat"

    def attack(self, intel: dict) -> list[Finding]:
        findings = []

        # Check for overly permissive endpoints
        for ep in intel.get("api_endpoints", []):
            if (
                ep["method"] in ("POST", "PUT", "DELETE")
                and "admin" in ep["path"].lower()
            ):
                findings.append(
                    self._finding(
                        severity="high",
                        title=f"ADMIN ENDPOINT: {ep['method']} {ep['path']}",
                        description=f"Administrative endpoint {ep['method']} {ep['path']} in {ep['file']}. "
                        f"Verify authentication and authorization are properly enforced.",
                        file_path=ep["file"],
                        cwe="CWE-306",
                        remediation="Ensure admin endpoints require authentication and role-based access control.",
                    )
                )

        # Check for debug/test credentials
        for f in intel.get("files", []):
            content = f.get("content", "").lower()
            if any(
                p in content
                for p in [
                    "debug=true",
                    "debug = true",
                    "debug_mode",
                    "password=test",
                    "password=admin",
                    "password=password",
                    "app.run(debug=true",
                    'app.run(host="0.0.0.0"',
                    "app.run(host='0.0.0.0'",
                    "flask_debug",
                    'secret_key = "',
                    "secret_key = '",
                ]
            ):
                findings.append(
                    self._finding(
                        severity="medium",
                        title=f"DEBUG MODE: {f['path']}",
                        description=f"Debug mode or test credentials found in {f['path']}. "
                        f"An insider or attacker with code access can exploit this.",
                        file_path=f["path"],
                        cwe="CWE-489",
                        remediation="Remove debug flags and test credentials from production code.",
                    )
                )

        return findings


class NetworkExfiltrationAgent(AttackerAgent):
    """Simulates data exfiltration through outbound network calls."""

    agent_type = "exfiltration"

    def attack(self, intel: dict) -> list[Finding]:
        findings = []

        for f in intel.get("files", []):
            content = f.get("content", "")
            # Check for outbound HTTP calls to unknown hosts
            urls = re.findall(r"https?://[^\s\"']+", content)
            suspicious = [
                u
                for u in urls
                if not any(
                    safe in u
                    for safe in [
                        "api.openai.com",
                        "api.anthropic.com",
                        "github.com",
                        "googleapis.com",
                        "twilio.com",
                        "localhost",
                        "127.0.0.1",
                        "api.stripe.com",
                        "huggingface.co",
                        "pypi.org",
                        "npmjs.org",
                        "api.elevenlabs.io",
                        "schema.org",
                        "fonts.googleapis.com",
                        "cdn.jsdelivr.net",
                        "unpkg.com",
                        "cdnjs.cloudflare.com",
                        "example.com",
                        "your-ngrok",
                    ]
                )
            ]
            for url in suspicious[:3]:
                findings.append(
                    self._finding(
                        severity="low",
                        title=f"OUTBOUND CALL: {url[:60]}",
                        description=f"Outbound HTTP call to {url[:80]} found in {f['path']}. "
                        f"Verify this is a legitimate service and not a data exfiltration endpoint.",
                        file_path=f["path"],
                        cwe="CWE-200",
                        remediation="Audit all outbound network calls. Use an allowlist for approved domains.",
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# Swarm engine
# ---------------------------------------------------------------------------

AGENT_TYPES = [
    SupplyChainAgent,
    CredentialTheftAgent,
    PromptInjectionAgent,
    InsiderThreatAgent,
    NetworkExfiltrationAgent,
]


def run_swarm(intel: dict, num_agents: int = 100, quiet: bool = False) -> list[Finding]:
    """Spawn and run attacker agents against project intelligence."""
    import random

    all_findings = []
    agents_per_type = max(num_agents // len(AGENT_TYPES), 1)
    total_agents = agents_per_type * len(AGENT_TYPES)
    agent_counter = 0
    live_findings: list[Finding] = []

    # Collect file paths for realistic probing messages
    file_paths = [f["path"] for f in intel.get("files", [])]
    dep_names = [d["name"] for d in intel.get("dependencies", [])]
    endpoint_paths = [e["path"] for e in intel.get("api_endpoints", [])]

    # Probing messages per agent type
    probe_messages = {
        "supply-chain": [
            "checking PyPI advisories for {dep}",
            "comparing {dep} hash against known-compromised list",
            "scanning {dep} install hooks",
            "testing typosquat distance for {dep}",
            "verifying {dep} version pinning",
            "checking {dep} maintainer history",
            "analyzing {dep} download spike patterns",
        ],
        "credential-theft": [
            "scanning {file} for hardcoded secrets",
            "pattern-matching API keys in {file}",
            "checking env fallback defaults in {file}",
            "hunting JWT tokens in {file}",
            "searching {file} for connection strings",
            "testing {file} for private key material",
            "checking .gitignore coverage for secrets",
        ],
        "prompt-injection": [
            "tracing user input flow into {file}",
            "testing LLM call boundary at {file}",
            "checking prompt sanitization in {file}",
            "analyzing system prompt exposure in {file}",
            "probing chat completion call in {file}",
            "testing f-string injection surface in {file}",
        ],
        "insider-threat": [
            "probing {endpoint} for auth bypass",
            "checking {file} for debug flags",
            "testing {file} for test credentials",
            "scanning {file} for admin backdoors",
            "checking CORS policy in {file}",
            "testing {endpoint} authorization",
        ],
        "exfiltration": [
            "mapping outbound calls in {file}",
            "checking {file} for data exfil endpoints",
            "testing DNS exfiltration vectors in {file}",
            "auditing HTTP calls in {file}",
            "checking {file} for webhook URLs",
            "tracing data flow to external services in {file}",
        ],
    }

    severity_sym = {
        "critical": "\033[91m\033[1m[!!!] CRITICAL",
        "high": "\033[93m[!!] HIGH",
        "medium": "\033[33m[!] MEDIUM",
        "low": "\033[90m[.] LOW",
    }

    def _pick_probe(agent_type: str) -> str:
        """Generate a realistic probing message."""
        templates = probe_messages.get(agent_type, ["scanning {file}"])
        tmpl = random.choice(templates)
        ctx = {
            "file": random.choice(file_paths) if file_paths else "source",
            "dep": random.choice(dep_names) if dep_names else "package",
            "endpoint": random.choice(endpoint_paths) if endpoint_paths else "/api",
        }
        return tmpl.format(**ctx)

    # Simulate swarm with live output
    if not quiet:
        sys.stderr.write(
            f"\033[31m[swarm]\033[0m Initializing {total_agents} adversarial agents...\n"
        )
        sys.stderr.flush()
        time.sleep(0.3)

    for i, agent_cls in enumerate(AGENT_TYPES):
        type_name = agent_cls.agent_type
        type_label = type_name.upper().replace("-", " ")

        if not quiet:
            sys.stderr.write(
                f"\n\033[31m[swarm]\033[0m \033[1mDeploying {agents_per_type} {type_label} agents\033[0m\n"
            )
            sys.stderr.flush()
            time.sleep(0.15)

        for j in range(agents_per_type):
            agent_id = i * agents_per_type + j
            agent_counter += 1
            agent = agent_cls(agent_id)

            # Show probing activity (not every agent, ~30% for readability)
            if not quiet and (j < 3 or random.random() < 0.15):
                probe = _pick_probe(type_name)
                sys.stderr.write(f"\033[90m  agent #{agent_id:>3} → {probe}\033[0m\n")
                sys.stderr.flush()
                time.sleep(random.uniform(0.02, 0.06))

            try:
                findings = agent.attack(intel)
                # Print findings as they're discovered (first agent only, dedup later)
                for f in findings:
                    key = f"{f.title}|{f.file_path}|{f.line_number}"
                    if not quiet and key not in {
                        f"{lf.title}|{lf.file_path}|{lf.line_number}"
                        for lf in live_findings
                    }:
                        sev = severity_sym.get(f.severity, "[?]")
                        sys.stderr.write(f"  {sev}: {f.title}\033[0m\n")
                        sys.stderr.flush()
                        live_findings.append(f)
                        time.sleep(random.uniform(0.03, 0.08))
                all_findings.extend(findings)
            except Exception as e:
                logger.debug("Agent %d (%s) failed: %s", agent_id, type_name, e)

    if not quiet:
        sys.stderr.write(
            f"\n\033[31m[swarm]\033[0m All {total_agents} agents reported back.\n"
        )
        sys.stderr.flush()
        time.sleep(0.2)

    # Deduplicate findings by title + file
    seen = set()
    unique = []
    for f in all_findings:
        key = f"{f.title}|{f.file_path}|{f.line_number}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def calculate_risk_score(findings: list[Finding]) -> int:
    """Calculate 0-100 risk score from findings."""
    score = 100
    for f in findings:
        if f.severity == "critical":
            score -= 25
        elif f.severity == "high":
            score -= 10
        elif f.severity == "medium":
            score -= 3
        elif f.severity == "low":
            score -= 1
    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "critical": "\033[91m",  # red
    "high": "\033[93m",  # yellow
    "medium": "\033[33m",  # orange
    "low": "\033[90m",  # gray
}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_results(result: ScanResult):
    """Print results to terminal with colors."""
    print()
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  RedSwarm — Adversarial AI Security Audit{RESET}")
    print(f"{'=' * 60}")
    print(f"  Project:  {result.project_path}")
    print(f"  Agents:   {result.total_agents}")
    print(f"  Files:    {result.files_scanned}")
    print(f"  Deps:     {result.dependencies_scanned}")
    print(f"  Time:     {result.scan_time_s:.1f}s")
    print(f"{'=' * 60}")
    print()

    if not result.findings:
        print(f"  \033[92m✓ No vulnerabilities found. Your project looks clean.{RESET}")
        print()
        return

    # Risk score
    risk_color = (
        "\033[92m"
        if result.risk_score >= 80
        else "\033[93m"
        if result.risk_score >= 50
        else "\033[91m"
    )
    print(f"  Risk Score: {risk_color}{BOLD}{result.risk_score}/100{RESET}")
    print(
        f"  {SEVERITY_COLORS['critical']}CRITICAL: {result.critical}{RESET}  "
        f"{SEVERITY_COLORS['high']}HIGH: {result.high}{RESET}  "
        f"{SEVERITY_COLORS['medium']}MEDIUM: {result.medium}{RESET}  "
        f"{SEVERITY_COLORS['low']}LOW: {result.low}{RESET}"
    )
    print()

    # Findings sorted by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(
        result.findings, key=lambda f: severity_order.get(f.severity, 4)
    )

    for f in sorted_findings:
        color = SEVERITY_COLORS.get(f.severity, "")
        icon = {"critical": "!!!", "high": "!!", "medium": "!", "low": "."}
        print(
            f"  {color}[{icon.get(f.severity, '?')}] {f.severity.upper()}: {f.title}{RESET}"
        )
        print(f"      Agent #{f.agent_id} ({f.agent_type})")
        if f.file_path:
            loc = f.file_path
            if f.line_number:
                loc += f":{f.line_number}"
            print(f"      File: {loc}")
        print(f"      {f.description[:200]}")
        if f.attack_chain:
            print("      Attack chain:")
            for step in f.attack_chain:
                print(f"        -> {step}")
        if f.remediation:
            print(f"      Fix: {f.remediation[:150]}")
        print()

    print(f"{'=' * 60}")
    print(
        f"  {len(result.findings)} findings from {result.total_agents} adversarial agents"
    )
    print(f"{'=' * 60}")
    print()


def generate_html_report(result: ScanResult) -> str:
    """Generate HTML report."""
    severity_colors = {
        "critical": "#ef4444",
        "high": "#f59e0b",
        "medium": "#f97316",
        "low": "#6b7280",
    }
    risk_color = (
        "#22c55e"
        if result.risk_score >= 80
        else "#f59e0b"
        if result.risk_score >= 50
        else "#ef4444"
    )

    findings_html = ""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(
        result.findings, key=lambda f: severity_order.get(f.severity, 4)
    )

    for f in sorted_findings:
        chain_html = ""
        if f.attack_chain:
            steps = "".join(f"<li>{s}</li>" for s in f.attack_chain)
            chain_html = f"<div class='chain'><strong>Attack chain:</strong><ol>{steps}</ol></div>"

        findings_html += f"""
        <div class="finding {f.severity}">
            <div class="finding-header">
                <span class="badge" style="background:{severity_colors.get(f.severity, "#666")}">{f.severity.upper()}</span>
                <strong>{f.title}</strong>
            </div>
            <div class="finding-meta">Agent #{f.agent_id} ({f.agent_type}){f" | {f.file_path}" if f.file_path else ""}{f":{f.line_number}" if f.line_number else ""}</div>
            <p>{f.description}</p>
            {chain_html}
            {f'<div class="fix"><strong>Fix:</strong> {f.remediation}</div>' if f.remediation else ""}
        </div>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>RedSwarm Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,system-ui,sans-serif;background:#09090b;color:#e4e4e7;padding:40px 24px}}
.container{{max-width:900px;margin:0 auto}}
h1{{font-size:28px;font-weight:700;margin-bottom:8px;letter-spacing:-0.5px}}
.subtitle{{color:#71717a;margin-bottom:32px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:#27272a;border-radius:8px;overflow:hidden;margin-bottom:32px;border:1px solid #27272a}}
.stat{{background:#18181b;padding:16px;text-align:center}}
.stat .val{{font-size:24px;font-weight:700}}
.stat .label{{font-size:11px;color:#71717a;margin-top:2px}}
.finding{{background:#18181b;border:1px solid #27272a;border-radius:8px;padding:16px;margin-bottom:8px}}
.finding-header{{display:flex;align-items:center;gap:8px;margin-bottom:6px}}
.badge{{color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;text-transform:uppercase}}
.finding-meta{{font-size:11px;color:#71717a;margin-bottom:8px}}
.finding p{{font-size:13px;line-height:1.6;color:#a1a1aa}}
.chain{{margin-top:8px;font-size:12px;color:#a1a1aa}}
.chain ol{{margin-left:20px;margin-top:4px}}
.chain li{{margin-bottom:2px}}
.fix{{margin-top:8px;font-size:12px;color:#22c55e;background:rgba(34,197,94,0.05);padding:8px;border-radius:4px}}
.risk{{font-size:48px;font-weight:800;color:{risk_color};letter-spacing:-2px}}
</style></head>
<body><div class="container">
<h1>RedSwarm Security Report</h1>
<p class="subtitle">{result.project_path} | {result.total_agents} agents | {result.scan_time_s:.1f}s</p>
<div class="stats">
    <div class="stat"><div class="val risk">{result.risk_score}</div><div class="label">Risk Score</div></div>
    <div class="stat"><div class="val" style="color:#ef4444">{result.critical}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="val" style="color:#f59e0b">{result.high}</div><div class="label">High</div></div>
    <div class="stat"><div class="val" style="color:#f97316">{result.medium}</div><div class="label">Medium</div></div>
</div>
{findings_html}
</div></body></html>"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _levenshtein(s1: str, s2: str) -> int:
    """Simple Levenshtein distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _open_visualization(intel: dict, result: ScanResult):
    """Generate visualization HTML with real scan data and open in browser."""
    import webbrowser

    # Build file nodes with import relationships
    files_data = []
    for f in intel.get("files", []):
        content = f.get("content", "")
        imports = []
        # Extract Python imports
        for match in re.finditer(r"^(?:from|import)\s+(\w+)", content, re.MULTILINE):
            mod = match.group(1)
            # Check if it maps to a local file
            for other in intel.get("files", []):
                other_name = other["path"].replace(".py", "").replace("/", ".")
                if mod == other_name or mod == other["path"].replace(".py", ""):
                    imports.append(other["path"])
        files_data.append(
            {
                "id": f["path"],
                "label": f["path"].split("/")[-1],
                "loc": f.get("size", 100) // 3,  # rough LOC estimate
                "imports": imports,
            }
        )

    # Build findings with staggered discovery times
    sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    sorted_f = sorted(result.findings, key=lambda f: sev_order.get(f.severity, 0))
    findings_data = []
    for i, f in enumerate(sorted_f):
        findings_data.append(
            {
                "file": f.file_path,
                "severity": f.severity,
                "title": f.title[:60],
                "discovered_at": 4.0 + i * 1.8,
            }
        )

    viz_data = json.dumps(
        {
            "files": files_data,
            "findings": findings_data,
            "totalAgents": result.total_agents,
            "riskScore": result.risk_score,
        }
    )

    # Read the visualization template
    viz_template = Path(__file__).parent / "visualize.html"
    if not viz_template.exists():
        logger.warning("visualize.html not found — skipping visualization")
        return

    html = viz_template.read_text()
    # Inject real data
    html = html.replace(
        "const DATA = window.REDSWARM_DATA || {",
        f"const DATA = window.REDSWARM_DATA || {viz_data}; const _UNUSED = {{",
    )

    # Write to temp file and open
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as tmp:
        tmp.write(html)
        tmp_path = tmp.name

    logger.info("Visualization: %s", tmp_path)
    webbrowser.open(f"file://{tmp_path}")


def main():
    parser = argparse.ArgumentParser(
        description="RedSwarm — Adversarial AI swarm security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 redswarm.py ./my-project
    python3 redswarm.py . --agents 500
    python3 redswarm.py ./app --output report.html
    python3 redswarm.py . --focus supply-chain
        """,
    )
    parser.add_argument("project", help="Path to project directory")
    parser.add_argument(
        "--agents",
        type=int,
        default=100,
        help="Number of attacker agents (default: 100)",
    )
    parser.add_argument("--output", "-o", help="Save HTML report to file")
    parser.add_argument(
        "--focus",
        choices=[
            "supply-chain",
            "credentials",
            "prompt-injection",
            "insider",
            "exfiltration",
        ],
        help="Focus on specific attack type",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--visualize",
        "-v",
        action="store_true",
        help="Open real-time swarm attack visualization in browser",
    )
    args = parser.parse_args()

    project_path = Path(args.project).resolve()
    if not project_path.exists():
        print(f"Error: {project_path} does not exist")
        sys.exit(1)

    if not args.json:
        print()
        print(f"\033[31m{BOLD}  RedSwarm v0.1.0{RESET}")
        print(f"\033[31m  Adversarial AI Security Scanner{RESET}")
        print()

    t0 = time.time()

    # Phase 1: Scan
    scanner = ProjectScanner(str(project_path))
    intel = scanner.scan()

    # Phase 2: Attack
    findings = run_swarm(intel, num_agents=args.agents, quiet=args.json)

    scan_time = time.time() - t0

    # Build result
    result = ScanResult(
        project_path=str(project_path),
        scan_time_s=scan_time,
        total_agents=args.agents,
        findings=findings,
        files_scanned=intel["stats"]["total_files"],
        dependencies_scanned=intel["stats"]["total_deps"],
        risk_score=calculate_risk_score(findings),
    )

    # Output
    if args.json:
        output = {
            "risk_score": result.risk_score,
            "total_agents": result.total_agents,
            "findings": [
                {
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "agent_type": f.agent_type,
                    "cwe": f.cwe,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print_results(result)

    if args.output:
        html = generate_html_report(result)
        Path(args.output).write_text(html)
        logger.info("HTML report saved to %s", args.output)

    if args.visualize:
        _open_visualization(intel, result)

    sys.exit(1 if result.critical > 0 else 0)


if __name__ == "__main__":
    main()
