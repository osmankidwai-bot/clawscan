#!/usr/bin/env python3
"""CLAWSCAN — Security scanner for OpenClaw AI agent setups."""

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

__version__ = "0.1.0"

# Grading thresholds
GRADES = [
    (90, "A"),
    (70, "B"),
    (50, "C"),
    (30, "D"),
    (0, "F"),
]


def get_grade(score):
    for threshold, letter in GRADES:
        if score >= threshold:
            return letter
    return "F"


# ---------------------------------------------------------------------------
# Individual checks — each returns (passed: bool, points: int, message: str)
# ---------------------------------------------------------------------------

# ---- Config Security (40 pts) ----

def check_config_exists(oc_path):
    """openclaw.json exists and is parseable (5 pts)."""
    cfg = oc_path / "openclaw.json"
    if not cfg.exists():
        return False, 5, "openclaw.json not found"
    try:
        with open(cfg) as f:
            json.load(f)
        return True, 5, "openclaw.json exists and is valid JSON"
    except (json.JSONDecodeError, OSError):
        return False, 5, "openclaw.json exists but is not valid JSON"


def _load_config(oc_path):
    cfg = oc_path / "openclaw.json"
    if not cfg.exists():
        return {}
    try:
        with open(cfg) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


API_KEY_PATTERNS = [
    re.compile(r'sk-[A-Za-z0-9]{20,}'),
    re.compile(r'key-[A-Za-z0-9]{20,}'),
    re.compile(r'eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}'),  # JWT
    re.compile(r'AKIA[A-Z0-9]{16}'),  # AWS
    re.compile(r'ghp_[A-Za-z0-9]{36}'),  # GitHub PAT
    re.compile(r'gho_[A-Za-z0-9]{36}'),  # GitHub OAuth
    re.compile(r'xox[bpas]-[A-Za-z0-9\-]{10,}'),  # Slack
]


def check_no_hardcoded_keys(oc_path):
    """No API keys hardcoded in config (10 pts)."""
    cfg = oc_path / "openclaw.json"
    if not cfg.exists():
        return True, 10, "No config file to check for keys"
    try:
        with open(cfg) as f:
            content = f.read()
    except OSError:
        return True, 10, "Could not read config"
    for pat in API_KEY_PATTERNS:
        if pat.search(content):
            return False, 10, "API keys/tokens found in openclaw.json"
    return True, 10, "No hardcoded API keys in config"


def check_gateway_auth(oc_path):
    """Gateway auth token is set (5 pts)."""
    cfg = _load_config(oc_path)
    gw = cfg.get("gateway", {})
    if isinstance(gw, dict) and gw.get("auth"):
        return True, 5, "Gateway auth configured"
    return False, 5, "Gateway auth not configured"


def check_gateway_bind(oc_path):
    """Gateway bind is not 0.0.0.0 without auth (5 pts)."""
    cfg = _load_config(oc_path)
    gw = cfg.get("gateway", {})
    if not isinstance(gw, dict):
        return True, 5, "No gateway config found"
    bind = gw.get("bind", "127.0.0.1")
    has_auth = bool(gw.get("auth"))
    if bind == "0.0.0.0" and not has_auth:
        return False, 5, "Gateway bound to 0.0.0.0 without auth"
    return True, 5, "Gateway bind is secure"


def check_https_configured(oc_path):
    """HTTPS/TLS configured for remote access (5 pts)."""
    cfg = _load_config(oc_path)
    gw = cfg.get("gateway", {})
    if not isinstance(gw, dict):
        return True, 5, "No gateway config (local-only is fine)"
    tls = gw.get("tls") or gw.get("https") or gw.get("ssl")
    bind = gw.get("bind", "127.0.0.1")
    if bind != "127.0.0.1" and not tls:
        return False, 5, "No HTTPS/TLS for remote access"
    return True, 5, "HTTPS/TLS configured or not needed"


def check_model_allowlist(oc_path):
    """Model allowlist is configured (5 pts)."""
    cfg = _load_config(oc_path)
    agents = cfg.get("agents", {})
    if isinstance(agents, dict):
        defaults = agents.get("defaults", {})
        if isinstance(defaults, dict):
            models = defaults.get("models")
            if models and models != "*" and models != ["*"]:
                return True, 5, "Model allowlist configured"
    return False, 5, "No model allowlist configured"


def check_exec_security(oc_path):
    """Exec security is not 'full' without allowlist (5 pts)."""
    cfg = _load_config(oc_path)
    exec_cfg = cfg.get("exec", {})
    if isinstance(exec_cfg, dict):
        security = exec_cfg.get("security", "")
        allowlist = exec_cfg.get("allowlist") or exec_cfg.get("allow")
        if security == "full" and not allowlist:
            return False, 5, "Exec security set to 'full' without allowlist"
    return True, 5, "Exec security is properly configured"


# ---- File Exposure (25 pts) ----

PASSWORD_PATTERNS = [
    re.compile(r'password\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'passwd\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'secret\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'api[_-]?key\s*[:=]\s*\S+', re.IGNORECASE),
]


def check_memory_passwords(oc_path):
    """MEMORY.md doesn't contain plaintext passwords (10 pts)."""
    mem = oc_path / "MEMORY.md"
    if not mem.exists():
        return True, 10, "No MEMORY.md found"
    try:
        with open(mem) as f:
            content = f.read()
    except OSError:
        return True, 10, "Could not read MEMORY.md"
    for pat in PASSWORD_PATTERNS:
        if pat.search(content):
            return False, 10, "Potential passwords/secrets found in MEMORY.md"
    return True, 10, "MEMORY.md clean of plaintext passwords"


def check_env_files(oc_path):
    """No .env files with secrets in workspace (5 pts)."""
    for env_file in oc_path.rglob(".env*"):
        if env_file.is_file():
            try:
                with open(env_file) as f:
                    content = f.read()
                for pat in API_KEY_PATTERNS + PASSWORD_PATTERNS:
                    if pat.search(content):
                        return False, 5, f".env file with secrets found: {env_file.name}"
            except OSError:
                continue
    return True, 5, "No .env files with secrets"


def check_private_keys(oc_path):
    """No private keys (SSH, PGP) in workspace (5 pts)."""
    begin_pattern = re.compile(r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----')
    for fpath in oc_path.rglob("*"):
        if not fpath.is_file():
            continue
        if fpath.stat().st_size > 1_000_000:
            continue
        try:
            with open(fpath, errors="ignore") as f:
                head = f.read(4096)
            if begin_pattern.search(head):
                return False, 5, f"Private key found: {fpath.name}"
        except OSError:
            continue
    return True, 5, "No private keys in workspace"


def check_workspace_permissions(oc_path):
    """Workspace permissions aren't world-readable (5 pts)."""
    try:
        mode = oc_path.stat().st_mode
        if mode & stat.S_IROTH:
            return False, 5, "Workspace is world-readable"
        return True, 5, "Workspace permissions are secure"
    except OSError:
        return True, 5, "Could not check workspace permissions"


# ---- Skill Security (20 pts) ----

KNOWN_SKILL_SOURCES = [
    "openclaw",
    "github.com/openclaw",
    "registry.openclaw.dev",
]


def check_skill_sources(oc_path):
    """Installed skills are from known sources (5 pts)."""
    skills_dir = oc_path / "skills"
    if not skills_dir.exists():
        return True, 5, "No skills directory"
    unknown = []
    for manifest in skills_dir.rglob("manifest.json"):
        try:
            with open(manifest) as f:
                data = json.load(f)
            source = data.get("source", "")
            if not any(ks in source for ks in KNOWN_SKILL_SOURCES):
                unknown.append(data.get("name", manifest.parent.name))
        except (json.JSONDecodeError, OSError):
            continue
    if unknown:
        return False, 5, f"Skills from unknown sources: {', '.join(unknown[:3])}"
    return True, 5, "All skills from known sources"


def check_skill_exec_override(oc_path):
    """No skills with exec security override to 'full' (5 pts)."""
    skills_dir = oc_path / "skills"
    if not skills_dir.exists():
        return True, 5, "No skills directory"
    for manifest in skills_dir.rglob("manifest.json"):
        try:
            with open(manifest) as f:
                data = json.load(f)
            if data.get("exec", {}).get("security") == "full":
                name = data.get("name", manifest.parent.name)
                return False, 5, f"Skill '{name}' overrides exec to 'full'"
        except (json.JSONDecodeError, OSError, AttributeError):
            continue
    return True, 5, "No skills with exec override to 'full'"


def check_skill_permissions(oc_path):
    """No skills requesting elevated permissions without justification (5 pts)."""
    skills_dir = oc_path / "skills"
    if not skills_dir.exists():
        return True, 5, "No skills directory"
    elevated = []
    for manifest in skills_dir.rglob("manifest.json"):
        try:
            with open(manifest) as f:
                data = json.load(f)
            perms = data.get("permissions", [])
            if isinstance(perms, list):
                for p in perms:
                    perm_name = p if isinstance(p, str) else p.get("name", "")
                    if perm_name in ("root", "sudo", "admin", "system", "full_access"):
                        justification = p.get("justification", "") if isinstance(p, dict) else ""
                        if not justification:
                            elevated.append(data.get("name", manifest.parent.name))
        except (json.JSONDecodeError, OSError):
            continue
    if elevated:
        return False, 5, f"Skills with unjustified elevated perms: {', '.join(elevated[:3])}"
    return True, 5, "No unjustified elevated permissions"


def check_skills_dir_writable(oc_path):
    """Skills directory isn't world-writable (5 pts)."""
    skills_dir = oc_path / "skills"
    if not skills_dir.exists():
        return True, 5, "No skills directory"
    try:
        mode = skills_dir.stat().st_mode
        if mode & stat.S_IWOTH:
            return False, 5, "Skills directory is world-writable"
        return True, 5, "Skills directory permissions are secure"
    except OSError:
        return True, 5, "Could not check skills directory permissions"


# ---- Network Security (15 pts) ----

def check_gateway_public(oc_path):
    """Gateway port isn't exposed on public IP without auth (5 pts)."""
    cfg = _load_config(oc_path)
    gw = cfg.get("gateway", {})
    if not isinstance(gw, dict):
        return True, 5, "No gateway configuration"
    bind = gw.get("bind", "127.0.0.1")
    has_auth = bool(gw.get("auth"))
    if bind not in ("127.0.0.1", "localhost", "::1") and not has_auth:
        return False, 5, "Gateway exposed on public IP without auth"
    return True, 5, "Gateway not publicly exposed without auth"


def check_webhooks_https(oc_path):
    """No webhooks configured without HTTPS (5 pts)."""
    cfg = _load_config(oc_path)
    webhooks = cfg.get("webhooks", [])
    if not isinstance(webhooks, list):
        webhooks = [webhooks] if isinstance(webhooks, dict) else []
    for wh in webhooks:
        url = wh.get("url", "") if isinstance(wh, dict) else str(wh)
        if url.startswith("http://"):
            return False, 5, "Webhook configured without HTTPS"
    return True, 5, "All webhooks use HTTPS (or none configured)"


def check_browser_cookies(oc_path):
    """Browser profile cookies aren't accessible to other users (5 pts)."""
    browser_dir = oc_path / "browser"
    if not browser_dir.exists():
        return True, 5, "No browser profile directory"
    cookie_files = list(browser_dir.rglob("*cookie*")) + list(browser_dir.rglob("*Cookie*"))
    for cf in cookie_files:
        if cf.is_file():
            try:
                mode = cf.stat().st_mode
                if mode & stat.S_IROTH:
                    return False, 5, "Browser cookies readable by other users"
            except OSError:
                continue
    return True, 5, "Browser cookies are secure"


# ---------------------------------------------------------------------------
# Scanner orchestration
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    # Config Security
    ("Config Security", check_config_exists),
    ("Config Security", check_no_hardcoded_keys),
    ("Config Security", check_gateway_auth),
    ("Config Security", check_gateway_bind),
    ("Config Security", check_https_configured),
    ("Config Security", check_model_allowlist),
    ("Config Security", check_exec_security),
    # File Exposure
    ("File Exposure", check_memory_passwords),
    ("File Exposure", check_env_files),
    ("File Exposure", check_private_keys),
    ("File Exposure", check_workspace_permissions),
    # Skill Security
    ("Skill Security", check_skill_sources),
    ("Skill Security", check_skill_exec_override),
    ("Skill Security", check_skill_permissions),
    ("Skill Security", check_skills_dir_writable),
    # Network Security
    ("Network Security", check_gateway_public),
    ("Network Security", check_webhooks_https),
    ("Network Security", check_browser_cookies),
]


def run_scan(oc_path, verbose=False):
    results = []
    total_score = 0
    max_score = 0
    for category, check_fn in ALL_CHECKS:
        passed, points, message = check_fn(oc_path)
        results.append({
            "category": category,
            "check": check_fn.__doc__.split("(")[0].strip() if check_fn.__doc__ else check_fn.__name__,
            "passed": passed,
            "points": points,
            "message": message,
        })
        max_score += points
        if passed:
            total_score += points

    grade = get_grade(total_score)
    return {
        "path": str(oc_path),
        "score": total_score,
        "max_score": max_score,
        "grade": grade,
        "results": results,
    }


def format_report(report, verbose=False):
    score = report["score"]
    max_score = report["max_score"]
    grade = report["grade"]
    results = report["results"]

    width = 44
    lines = []
    lines.append("╔" + "═" * width + "╗")
    lines.append("║" + "CLAWSCAN Security Report".center(width) + "║")
    lines.append("╠" + "═" * width + "╣")
    lines.append("║" + f"  Grade: {grade} ({score}/{max_score})".ljust(width) + "║")
    lines.append("╠" + "═" * width + "╣")

    current_cat = None
    for r in results:
        if not verbose and r["passed"]:
            if r["category"] != current_cat:
                current_cat = r["category"]
            continue

        if r["category"] != current_cat:
            current_cat = r["category"]
            cat_line = f"  [{current_cat}]"
            lines.append("║" + cat_line.ljust(width) + "║")

        if r["passed"]:
            icon = "✅"
        else:
            icon = "❌"
        msg = f"  {icon} {r['message']}"
        if len(msg) > width:
            msg = msg[:width - 1] + "…"
        lines.append("║" + msg.ljust(width) + "║")

    lines.append("╠" + "═" * width + "╣")
    lines.append("║" + "  Pro upgrade: 12 additional checks".ljust(width) + "║")
    lines.append("║" + "  → clawscan.app/pro".ljust(width) + "║")
    lines.append("╚" + "═" * width + "╝")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="CLAWSCAN — Security scanner for OpenClaw AI agent setups",
    )
    parser.add_argument(
        "--path",
        default=os.path.expanduser("~/.openclaw"),
        help="Path to OpenClaw directory (default: ~/.openclaw/)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show all checks, not just failures",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"clawscan {__version__}",
    )
    args = parser.parse_args()

    oc_path = Path(args.path)
    if not oc_path.exists():
        print(f"Error: Path '{oc_path}' does not exist.")
        print(f"Hint: Run with --path /your/openclaw/dir or create {oc_path}")
        sys.exit(1)

    report = run_scan(oc_path, verbose=args.verbose)

    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        print()
        print(format_report(report, verbose=args.verbose))
        print()


if __name__ == "__main__":
    main()
