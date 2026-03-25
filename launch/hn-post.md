# Hacker News Post

## Title
Show HN: RedSwarm – Adversarial AI security scanner, one file, zero dependencies

## Body
Hey HN,

After the LiteLLM supply chain attack this week (credential stealer injected via a compromised Trivy integration in CI/CD), I wanted a tool that could simulate these kinds of attacks against a codebase before they reach production.

RedSwarm is a single-file Python tool with zero external dependencies. It spawns hundreds of concurrent "attacker agents" that probe your codebase for vulnerabilities across five categories: supply chain compromise, credential theft, prompt injection, insider threat, and data exfiltration.

Each agent type has its own attack model and heuristics. They fan out across the file tree in parallel, scoring findings by severity. You get a 0-100 risk score at the end, with color terminal output, an HTML report, or JSON for CI/CD integration.

Technical details:

- Pure Python, stdlib only. No pip install needed.
- Static analysis only — it never executes your code or makes network calls.
- Tested against a 441-file production app: found 20 critical issues in 4.8 seconds.
- Designed to be dropped into any project or pipeline with minimal friction.

Limitations I want to be upfront about:

- This is static heuristic analysis, not formal verification. It will have false positives.
- It does not replace manual security review or dynamic testing.
- The agent models are pattern-based, not LLM-powered — they are fast and deterministic but not as flexible as a human auditor.
- Coverage across languages is uneven right now. Python and JS/TS are strongest.

Most static analysis tools ask "does this code follow rules?" RedSwarm asks "how would an attacker exploit this code?"

Source: https://github.com/beee003/redswarm

Happy to answer questions about the approach or where this should go next.
