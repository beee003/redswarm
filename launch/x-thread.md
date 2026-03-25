# X/Twitter Thread

## Tweet 1
Yesterday a credential stealer was injected into LiteLLM via a compromised Trivy CI/CD pipeline.

It sat there for hours before anyone noticed.

I built RedSwarm to find attacks like this before they ship. Open source, one file, zero dependencies.

github.com/beee003/redswarm

## Tweet 2
How it works:

RedSwarm spawns hundreds of adversarial "attacker agents" against your codebase — each one simulating a real attack pattern.

5 agent types:
- Supply chain compromise
- Credential theft
- Prompt injection
- Insider threat
- Data exfiltration

It thinks like an attacker so you don't have to.

## Tweet 3
Ran it against a 441-file production app.

20 CRITICAL vulnerabilities found in 4.8 seconds.

Color-coded terminal output, risk score 0-100, plus HTML reports you can share with your team and JSON output for CI/CD pipelines.

## Tweet 4
What it won't do:

- It's not a replacement for a full pentest
- It doesn't execute code or make network calls against your infra
- It's static analysis with an adversarial mindset

What it will do: surface the stuff you missed at 3am before someone else finds it.

## Tweet 5
The LiteLLM attack was a wake-up call. Supply chain security isn't someone else's problem — it's in your CI pipeline right now.

RedSwarm is MIT licensed, one file, zero dependencies.

Star it, fork it, run it against your own code tonight.

github.com/beee003/redswarm
