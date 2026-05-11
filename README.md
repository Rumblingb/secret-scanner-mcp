# Secret Scanner MCP Server

Detect leaked API keys, tokens, passwords, and private keys in text, files, or directories — directly via the Model Context Protocol (MCP).

## Overview

Secret Scanner is an MCP server that helps AI agents and developers identify accidentally exposed credentials before they cause a breach. With 40+ regex patterns covering major providers, it scans text, files, directories, and git history for leaked secrets.

## Tools

| Tool | Description |
|------|-------------|
| `scan_text(text)` | Scan any text for API keys, tokens, passwords, private keys |
| `scan_file(path)` | Scan a file for leaked secrets |
| `scan_directory(path, max_file_size_mb?, include_patterns?)` | Recursively scan a directory |
| `scan_git_history(path, max_commits?)` | Scan git commit history for committed secrets |
| `mask_secrets(text)` | Replace all detected secrets with `[REDACTED]` |

## Supported Patterns (40+)

### Critical
- **Stripe**: `sk_live_*`, `rk_live_*`
- **GitHub**: `ghp_*`, `gho_*`, `ghu_*`, `ghr_*`, `github_pat_*`
- **AWS**: `AKIA*`, Secret Access Keys
- **Google**: `AIza*` API Keys, OAuth Client Secrets
- **OpenAI**: `sk-*`, `sk-proj-*`
- **Anthropic**: `sk-ant-*`, `sk-ant-api03-*`
- **Slack**: Bot tokens (`xoxb-*`), User tokens (`xoxp-*`), Webhooks
- **Discord**: Bot tokens, Webhook URLs
- **JWT Tokens**
- **Private Keys**: RSA, EC, OpenSSH, PGP

### High
- **Databases**: PostgreSQL, MySQL, MongoDB, Redis connection strings
- **GitLab**: Personal tokens (`glpat-*`), CI tokens (`glci-*`)
- **Square**: Access tokens (`sq0atp-*`), Secret keys (`sq0csp-*`)
- **Twilio**: API Keys, Auth Tokens
- **Telegram Bot Tokens**
- **NPM**, **PyPI**, **Docker Hub** tokens
- **SendGrid**, **Mailgun**, **Datadog** API keys
- **Hugging Face** tokens (`hf_*`)

### Medium
- Generic password/secret assignments
- Basic auth in URLs
- Bearer tokens in headers
- Cookie/session secrets
- **Cloudflare**, **SonarQube**, **Pulumi** tokens

### Low
- AWS Account IDs
- Internal IP addresses (RFC 1918)
- S3 bucket endpoints
- Email addresses

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### With an MCP Client

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "secret-scanner": {
      "command": "python",
      "args": ["/path/to/secret-scanner-mcp/server.py"]
    }
  }
}
```

### Direct Invocation

```bash
python server.py
```

### Example: scan_text

```json
{
  "text": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\npassword=super_secret_123"
}
```

Returns:

```json
{
  "scan_type": "text",
  "total_findings": 1,
  "summary_by_severity": { "critical": 1, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "type": "AWS Access Key ID",
      "value": "AKIA****AMPLE",
      "severity": "critical",
      "category": "aws",
      "line": 1,
      "column": 9,
      "context": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
    }
  ]
}
```

### Example: mask_secrets

```json
{
  "text": "My OpenAI key is sk-abc123def456 and my password is secret!"
}
```

Returns:

```json
{
  "original_length": 52,
  "masked_length": 52,
  "secrets_redacted": 2,
  "masked_text": "My OpenAI key is [REDACTED-OpenAI API Key] and my password is [REDACTED-Generic Password Assignment]!"
}
```

## Why Use Secret Scanner?

- **Security-first**: Catch leaked credentials before they reach production
- **CI/CD integration**: Run scans as part of your build pipeline
- **Git history scanning**: Find secrets that were already committed
- **AI-ready**: Every AI agent developer can use it to check configs, env files, and chat logs for leaked keys
- **Comprehensive**: 40+ patterns covering Stripe, GitHub, AWS, Google, OpenAI, Anthropic, Slack, Discord, and more

## Pricing

**$19/month** — Single developer license with unlimited scans.

Support development: [Buy a license](https://buy.stripe.com/dRm6oJ4Hd2Jugek0wz1oI0m)

## License

Proprietary — see LICENSE file for details.
