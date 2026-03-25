<p align="center">
  <h1 align="center">RedSwarm</h1>
  <p align="center"><strong>Adversarial AI swarm that attacks your codebase before hackers do.</strong></p>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#how-it-works">How it works</a> •
  <a href="#attack-agents">Attack agents</a> •
  <a href="#output">Output</a> •
  <a href="#why">Why</a>
</p>

---

**RedSwarm** spawns hundreds of adversarial AI agents that simulate real-world attacks against your codebase. Supply chain attacks, credential theft, prompt injection, insider threats, data exfiltration — all in one scan.

Zero dependencies. One file. Works on any project.

```
$ python3 redswarm.py ./my-app --agents 500

  RedSwarm v0.1.0
  Adversarial AI Security Scanner

============================================================
  RedSwarm — Adversarial AI Security Audit
============================================================
  Project:  /home/user/my-app
  Agents:   500
  Files:    441
  Deps:     41
  Time:     4.8s
============================================================

  Risk Score: 12/100
  CRITICAL: 20  HIGH: 1  MEDIUM: 52  LOW: 318

  [!!!] CRITICAL: COMPROMISED PACKAGE: litellm
       Agent #3 (supply-chain)
       Supply chain attack via Trivy CI/CD compromise.
       Credential stealer + K8s lateral movement.
       Attack chain:
         -> Attacker compromises litellm on PyPI
         -> Malicious code executes on pip install
         -> Credentials, SSH keys, and secrets exfiltrated
         -> Lateral movement to connected infrastructure

  [!!!] CRITICAL: EXPOSED SECRET: Hardcoded API key
       Agent #112 (credential-theft)
       Found Hardcoded API key in config.py: api_key="sk-...
```

## Quickstart

```bash
# Clone
git clone https://github.com/mayawalcher/redswarm.git
cd redswarm

# Scan any project
python3 redswarm.py /path/to/your/project

# More agents = more thorough
python3 redswarm.py . --agents 500

# HTML report
python3 redswarm.py . --agents 500 --output report.html

# JSON for CI/CD
python3 redswarm.py . --json

# Focus on specific attack type
python3 redswarm.py . --focus supply-chain
```

No dependencies. No API keys. Just Python 3.10+.

## How it works

```
┌─────────────────────────────────────────────────────────┐
│                    PROJECT SCANNER                        │
│  Collects intelligence: files, deps, secrets, endpoints  │
│  LLM calls, env files, API surface                       │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                   SWARM ENGINE                           │
│  Spawns N attacker agents across 5 attack categories     │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ Supply   │ │Credential│ │ Prompt   │ │ Insider  │   │
│  │ Chain    │ │ Theft    │ │Injection │ │ Threat   │   │
│  │ x100     │ │ x100     │ │ x100     │ │ x100     │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│  ┌──────────┐                                           │
│  │  Exfil   │  Each agent runs independently,           │
│  │  x100    │  findings are deduplicated                 │
│  └──────────┘                                           │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                 RISK ASSESSMENT                           │
│  0-100 score, severity classification, attack chains     │
│  Terminal output, HTML report, or JSON for CI/CD         │
└─────────────────────────────────────────────────────────┘
```

## Attack agents

### Supply Chain Agent
Inspired by the [LiteLLM supply chain attack](https://www.bleepingcomputer.com/news/security/litellm-supply-chain-attack/) (March 2026). Detects:
- **Known compromised packages** — litellm, ultralytics, event-stream, ua-parser-js, colors, faker
- **Typosquatting** — packages with names suspiciously similar to popular ones
- **Unpinned versions** — dependencies without version locks that could auto-update to malicious releases

### Credential Theft Agent
- **Hardcoded secrets** — API keys (OpenAI, Anthropic, AWS, GitHub, Slack, Google, etc.)
- **Leaked credentials** — JWT tokens, database connection strings, private keys
- **Env file exposure** — .env files with sensitive keys that might be committed to git
- **Default fallbacks** — API keys hardcoded as `os.getenv()` fallback values

### Prompt Injection Agent
- **Direct injection** — user input flowing into LLM system prompts
- **Indirect injection** — request data reaching chat completion calls
- **Unvalidated outputs** — LLM calls without output sanitization

### Insider Threat Agent
- **Admin endpoints** — unprotected administrative API routes
- **Debug mode** — Flask/Django debug mode enabled, `app.run(host="0.0.0.0")`
- **Test credentials** — hardcoded passwords, default accounts

### Network Exfiltration Agent
- **Suspicious outbound calls** — HTTP requests to unrecognized domains
- **Data exfiltration endpoints** — unexpected external API calls in source code

## Output

### Terminal (default)
Color-coded findings with severity badges, attack chains, and remediation steps.

### HTML Report (`--output report.html`)
Dark-themed security report with risk score dashboard, severity breakdown, and detailed findings.

### JSON (`--json`)
Machine-readable output for CI/CD integration. Exit code 1 if any CRITICAL findings.

```json
{
  "risk_score": 37,
  "total_agents": 100,
  "findings": [
    {
      "severity": "critical",
      "title": "EXPOSED SECRET: Hardcoded API key",
      "file": "config.py",
      "cwe": "CWE-798",
      "remediation": "Remove secret from source code..."
    }
  ]
}
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: RedSwarm Security Scan
  run: |
    python3 redswarm.py . --json --agents 200 > redswarm.json
    # Fails on critical findings (exit code 1)
```

## Why

On March 24, 2026, LiteLLM — a package used by thousands of AI companies — was [compromised via a supply chain attack](https://www.bleepingcomputer.com/news/security/litellm-supply-chain-attack/). A credential stealer was injected through a Trivy CI/CD compromise, and the malicious package was downloaded before PyPI quarantined it.

Traditional scanners check a database of known CVEs. RedSwarm thinks like an attacker — it simulates the full attack chain across your codebase, dependencies, secrets, LLM calls, and API surface simultaneously.

The swarm approach means every agent independently discovers vulnerabilities. More agents = more coverage. The findings are deduplicated and scored into a single risk assessment.

## Roadmap

- [ ] GitHub App — auto-scan PRs
- [ ] VS Code extension
- [ ] LLM-powered deep analysis (optional, with API key)
- [ ] Custom agent plugins
- [ ] SARIF output for GitHub Security tab
- [ ] Docker image scanning
- [ ] Terraform/CloudFormation analysis

## License

MIT
