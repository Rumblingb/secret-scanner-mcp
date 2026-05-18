#!/usr/bin/env python3
"""Secret Scanner MCP — Detect leaked API keys, tokens, and secrets in text/files."""

import json, re, os, base64
from mcp.server.lowlevel import Server, stdio_server

server = Server("secret-scanner-mcp")

# ─── 30+ regex patterns for major providers ──────────────────────────────────

SECRET_PATTERNS = [
    # Stripe
    (r'(?i)sk_live_[0-9a-z-A-Z]{16,}', "Stripe Live Secret Key", "CRITICAL"),
    (r'(?i)rk_live_[0-9a-z-A-Z]{16,}', "Stripe Live Restricted Key", "CRITICAL"),
    (r'(?i)sk_test_[0-9a-z-A-Z]{16,}', "Stripe Test Secret Key", "HIGH"),
    (r'(?i)pk_live_[0-9a-z-A-Z]{16,}', "Stripe Live Publishable Key", "LOW"),
    (r'(?i)whsec_[0-9a-z-A-Z]{16,}', "Stripe Webhook Secret", "HIGH"),
    # GitHub
    (r'(?i)ghp_[0-9a-zA-Z]{36,}', "GitHub Personal Access Token", "CRITICAL"),
    (r'(?i)gho_[0-9a-zA-Z]{36,}', "GitHub OAuth Access Token", "CRITICAL"),
    (r'(?i)ghu_[0-9a-zA-Z]{36,}', "GitHub User Token", "CRITICAL"),
    (r'(?i)ghs_[0-9a-zA-Z]{36,}', "GitHub App Token", "CRITICAL"),
    (r'(?i)ghr_[0-9a-zA-Z]{36,}', "GitHub Refresh Token", "CRITICAL"),
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "CRITICAL"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}', "AWS Secret Access Key", "CRITICAL"),
    # Google
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key", "HIGH"),
    (r'(?i)google[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{39}', "Google API Key", "HIGH"),
    # OpenAI
    (r'sk-[A-Za-z0-9]{20,}', "OpenAI API Key", "CRITICAL"),
    (r'sk-proj-[A-Za-z0-9_-]{20,}', "OpenAI Project Key", "CRITICAL"),
    (r'sk-svcacct-[A-Za-z0-9_-]{20,}', "OpenAI Service Account Key", "CRITICAL"),
    # Anthropic
    (r'sk-ant-[A-Za-z0-9_-]{24,}', "Anthropic API Key", "CRITICAL"),
    (r'sk-ant-sid-[A-Za-z0-9_-]{24,}', "Anthropic Workspace Key", "CRITICAL"),
    # Slack
    (r'xox[baprs]-[0-9a-zA-Z-]{24,}', "Slack Token", "HIGH"),
    # Discord
    (r'(?i)discord[_-]?(?:bot[_-]?)?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}', "Discord Bot Token", "CRITICAL"),
    (r'[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}', "Discord Token", "HIGH"),
    # JWT
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "JWT Token", "MEDIUM"),
    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key", "CRITICAL"),
    (r'-----BEGIN CERTIFICATE-----', "Certificate", "MEDIUM"),
    # Generic passwords/tokens
    (r'(?i)(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?(?!\*)(?!x{3,})(?!.{256,})(.{6,50})["\']', "Password", "HIGH"),
    (r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']', "API Key", "HIGH"),
    (r'(?i)(?:secret|token)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']', "Secret/Token", "HIGH"),
    # Database URLs
    (r'postgres(?:ql)?://[^:]+:[^@]+@', "PostgreSQL Database URL", "CRITICAL"),
    (r'mysql://[^:]+:[^@]+@', "MySQL Database URL", "CRITICAL"),
    (r'mongodb(?:\+srv)?://[^:]+:[^@]+@', "MongoDB Database URL", "CRITICAL"),
    (r'redis://[^:]+:[^@]+@', "Redis Database URL", "HIGH"),
    # Heroku
    (r'(?i)heroku[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9-]{36}', "Heroku API Key", "HIGH"),
    # Telegram
    (r'\d{8,10}:[A-Za-z0-9_-]{35}', "Telegram Bot Token", "HIGH"),
    # SendGrid
    (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', "SendGrid API Key", "HIGH"),
    # Twilio
    (r'SK[A-Za-z0-9]{32}', "Twilio API Key", "HIGH"),
    # npm
    (r'(?i)npm[_-]?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9-]{36}', "npm Token", "HIGH"),
    # GitLab
    (r'glpat-[A-Za-z0-9_-]{20,}', "GitLab Personal Access Token", "HIGH"),
    # Docker
    (r'dckr_pat_[A-Za-z0-9_-]{26,}', "Docker Hub Token", "HIGH"),
]

@server.tool(
    name="scan_text",
    description="Scan text for leaked API keys, tokens, passwords, and secrets.",
    input_schema={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Text to scan for secrets"},
            "mask": {"type": "boolean", "description": "Return masked version of text", "default": False}
        },
        "required": ["text"]
    }
)
async def scan_text(text: str, mask: bool = False) -> str:
    try:
        findings = []
        masked = text
        
        for pattern, name, severity in SECRET_PATTERNS:
            for match in re.finditer(pattern, text):
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()
                # Redact the actual secret in context
                secret_val = match.group(0)
                redacted = secret_val[:8] + "..." + secret_val[-4:] if len(secret_val) > 12 else "[REDACTED]"
                safe_context = context.replace(secret_val, redacted)
                
                findings.append({
                    "type": name,
                    "severity": severity,
                    "value": redacted,
                    "length": len(secret_val),
                    "position": match.start(),
                    "context": safe_context[:150],
                    "recommended_action": "Rotate immediately" if severity == "CRITICAL" else "Verify and rotate if active"
                })
                
                if mask:
                    masked = masked.replace(secret_val, f"[REDACTED_{name.upper().replace(' ','_')}]")
        
        # Deduplicate
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["type"], f["position"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        critical = sum(1 for f in unique_findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in unique_findings if f["severity"] == "HIGH")
        
        result = {
            "total_findings": len(unique_findings),
            "critical": critical,
            "high": high,
            "medium": sum(1 for f in unique_findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in unique_findings if f["severity"] == "LOW"),
            "findings": unique_findings[:50],
            "severity_summary": f"{critical} critical, {high} high severity secrets found"
        }
        
        if mask:
            result["masked_text"] = masked
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "isError": True}, indent=2)

@server.tool(
    name="scan_file",
    description="Scan a file for leaked secrets.",
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to file to scan"}
        },
        "required": ["path"]
    }
)
async def scan_file(path: str) -> str:
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
        
        result = await scan_text(content)
        data = json.loads(result)
        data["file"] = path
        data["file_size"] = len(content)
        return json.dumps(data, indent=2)
    except FileNotFoundError:
        return json.dumps({"error": f"File not found: {path}", "isError": True}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "isError": True}, indent=2)

@server.tool(
    name="scan_directory",
    description="Recursively scan a directory for leaked secrets in all files.",
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Directory path to scan"},
            "max_files": {"type": "integer", "description": "Max files to scan", "default": 100},
            "exclude_patterns": {"type": "string", "description": "Comma-separated patterns to exclude (e.g. .git,node_modules,venv)", "default": ".git,node_modules,venv,__pycache__,.npm,.cache"}
        },
        "required": ["path"]
    }
)
async def scan_directory(path: str, max_files: int = 100, exclude_patterns: str = ".git,node_modules,venv,__pycache__,.npm,.cache") -> str:
    try:
        excludes = [p.strip() for p in exclude_patterns.split(",")]
        findings = []
        files_scanned = 0
        
        for root, dirs, files in os.walk(path):
            # Skip excluded dirs
            dirs[:] = [d for d in dirs if d not in excludes]
            if any(ex in root for ex in excludes):
                continue
            
            for fname in files:
                if files_scanned >= max_files:
                    break
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    result = await scan_text(content)
                    data = json.loads(result)
                    if data["total_findings"] > 0:
                        findings.append({
                            "file": fpath,
                            "findings_count": data["total_findings"],
                            "findings": data["findings"][:5]
                        })
                    files_scanned += 1
                except:
                    files_scanned += 1
                    continue
        
        return json.dumps({
            "directory": path,
            "files_scanned": files_scanned,
            "files_with_secrets": len(findings),
            "total_secrets_found": sum(f["findings_count"] for f in findings),
            "results": findings,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "isError": True}, indent=2)

@server.tool(
    name="mask_secrets",
    description="Replace all secrets in text with [REDACTED] placeholders.",
    input_schema={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Text containing secrets to mask"}
        },
        "required": ["text"]
    }
)
async def mask_secrets(text: str) -> str:
    try:
        result = await scan_text(text, mask=True)
        data = json.loads(result)
        return json.dumps({
            "original_length": len(text),
            "secrets_found": data["total_findings"],
            "critical": data["critical"],
            "masked_text": data.get("masked_text", text),
            "note": "Review masked text before sharing. Secrets have been replaced with [REDACTED_*] markers."
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "isError": True}, indent=2)

def main():
    import anyio
    async def run():
        async with stdio_server() as streams:
            await server.run(streams[0], streams[1], server.create_initialization_options())
    anyio.run(run)

if __name__ == "__main__":
    main()
