---
title: "Secrets Scanner: Find API Keys in Code"
description: "Paste a .env, config file or code snippet and find leaked API keys, tokens, private keys and passwords before you commit. Runs locally, nothing uploaded."
intro: "**SafeEnv** scans text for leaked credentials: AWS, GitHub, Stripe, OpenAI and Slack keys, private key blocks, passwords in connection strings and high-entropy values next to names like `SECRET` or `TOKEN`. Paste or drop a file; the scan happens entirely in your browser."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["secrets scanner", "api key leak checker", "find secrets in code", "env file scanner", "detect hardcoded passwords", "credential scanner", "github token leak", "secret detection online"]
tags: ["security", "devsecops", "secrets", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/secrets-scanner/"
tool_title: "SafeEnv secrets scanner"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Paste the content of a `.env`, `docker-compose.yml`, CI config, Terraform file or source snippet into the box, or use **Scan a file…** or drag a file onto it."
  - "Press **Scan for secrets**. A typical config file is scanned in a few milliseconds."
  - "Read the summary chips (critical, high, medium, low, info) and the findings list, sorted by severity and then by line number."
  - "Each finding shows the rule that matched, the line, a masked value (first and last four characters only) and what to do about it."
  - "Fix the critical items first: rotate the credential, remove it from the file and its git history, and load it from a secret manager or environment variable. **Copy report** gives you a text summary for a ticket."
faq:
  - q: "Is it safe to paste real secrets into this scanner?"
    a: "The scanner is JavaScript running in this page and makes no network requests with your text, so nothing reaches our servers. Masked values are shown on screen, never full secrets. That said, if you find a real production key, assume it is already compromised and rotate it."
  - q: "What kinds of secrets does it detect?"
    a: "Twenty specific formats, including AWS access key IDs and secret keys, GitHub and GitLab tokens, Stripe live and test keys, Google API keys, OpenAI and Anthropic API keys, Slack tokens and webhooks, SendGrid, npm, PyPI, Telegram bot and Twilio keys, JSON Web Tokens, private key blocks and credentials inside database or HTTP URLs. A second pass flags high-entropy values and hardcoded passwords in any `KEY=VALUE` line."
  - q: "Why is a value flagged as \"high entropy\"?"
    a: "Random-looking strings are what generated secrets look like. The scanner computes the Shannon entropy of each value of 20 or more characters and flags it at 4.3 bits per character or above. Values next to names containing secret, token, password, key or auth are rated higher. Hashes, UUIDs and build IDs can trigger it too, so check the context."
  - q: "What should I do if a secret was committed to git?"
    a: "Deleting the line in a new commit is not enough: the secret stays in the history and in every clone. Rotate or revoke the credential first, then rewrite history with `git filter-repo` or BFG Repo-Cleaner, force-push, and ask collaborators to re-clone. Rotation is the step that actually protects you."
  - q: "Does it replace tools like Gitleaks or GitHub secret scanning?"
    a: "No, it complements them. Use a pre-commit hook or CI scanner for every commit, and GitHub's push protection on your repositories. SafeEnv is for the moments in between: checking a snippet before you paste it into a chat, a ticket or an AI assistant, or reviewing a config someone sent you."
  - q: "Why are placeholder values listed as info?"
    a: "Lines such as `API_KEY=your-api-key-here` or `PASSWORD=${DB_PASSWORD}` match the shape of a secret but are templates. The scanner recognises common placeholder patterns (your-, changeme, example, xxx, `${VAR}`, `<value>`) and reports them as info so you can confirm they are intentional."
---

## How it works

The scanner is a small, dependency-free rules engine. It runs two passes over the text.

### Pass 1: known token formats

Twenty regular expressions match formats that providers document publicly, mostly by their fixed prefix and length. A few examples of what the rules look for:

| Rule | Signature it matches | Severity |
|---|---|---|
| Private key block | `-----BEGIN … PRIVATE KEY-----` (RSA, EC, DSA, OpenSSH, PGP, encrypted) | Critical |
| AWS access key ID | `AKIA`, `ASIA`, `ABIA` or `ACCA` followed by 16 uppercase letters or digits | Critical |
| AWS secret access key | A 40-character Base64 value assigned to a name like `aws_secret_access_key` | Critical |
| GitHub token | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` or `github_pat_` prefixes | Critical |
| Stripe live key | `sk_live_` / `rk_live_` prefixes | Critical |
| OpenAI / Anthropic key | `sk-proj-`, `sk-svcacct-`, `sk-ant-` prefixes | Critical |
| Google API key | `AIza` followed by 35 characters | High |
| Slack token / webhook | `xox[baprs]-` tokens, `hooks.slack.com/services/…` URLs | High |
| Credentials in a URI | `postgres://user:password@host`, also MySQL, MongoDB, Redis, AMQP, FTP and HTTP basic auth | High |
| JSON Web Token | Three Base64URL segments starting with `eyJ` | Medium |
| Stripe test / publishable key | `sk_test_`, `pk_live_`, `pk_test_` | Low |

Each match records the line number (counted from the newline characters before it) and a **masked** version of the value. The masked value keeps only the first and last four characters, so the report itself never contains the secret.

### Pass 2: generic `KEY=VALUE` analysis

Lines not already caught by a specific rule are parsed as assignments, the syntax of `.env` files, YAML and most config formats (`export` prefixes, quotes and trailing `#` comments are handled). For each value of six characters or more:

1. If it looks like a **placeholder** (`your-…`, `changeme`, `example`, `xxxx`, `${VAR}`, `<value>`, `true/false/null`), it is reported as *info* when the key name is secret-like, and otherwise ignored.
2. Values containing a URL or spaces are skipped, as they are rarely secrets on their own.
3. The **Shannon entropy** is computed as H = −Σ p·log₂(p) over the character frequencies. A value of 20+ characters with H ≥ 4.3 bits per character is flagged as *high entropy*, at high severity if the key name contains secret, token, passw, pwd, api_key, private, credential or auth, and medium otherwise.
4. A lower-entropy value assigned to a password-like name is reported as a *hardcoded password*.

Findings are sorted by severity, then by line. Nothing is stored: clear the box or close the tab and the text is gone.

### Limits

Regex scanning finds *formats*, not *validity*: it cannot tell whether a key is still active. It also cannot see secrets that are split across lines, encrypted, or encoded in unusual ways. That is why it is a quick check, not a replacement for scanning in your CI pipeline.

## Use cases

- **Before sharing a snippet.** Check a config or stack trace before pasting it into Slack, a GitHub issue, Stack Overflow or an AI chatbot.
- **Before the first commit.** Scan a new project's `.env.example`, `docker-compose.yml` and CI files to make sure no real value slipped in.
- **Reviewing a pull request or a handover.** Paste the diff of configuration files and look for anything critical.
- **Incident response.** After a suspected leak, scan exported logs or configs to list every credential that needs rotating.
- **Teaching secure habits.** The sample file shows a team, in seconds, how many secrets an ordinary `.env` contains.
