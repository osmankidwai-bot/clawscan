# ClawScan Security — Skill Architecture

## Vision

The definitive security skill for OpenClaw. Not a one-shot scanner — a living security layer that hardens, monitors, learns, and remediates. Ships as a ClawHub skill, installs in one command.

---

## Skill Structure

```
clawscan/
├── SKILL.md                    # Core workflow + tier routing
├── scripts/
│   ├── scan.sh                 # Main scanner (bash, zero deps)
│   ├── remediate.sh            # Auto-fix engine (safe fixes only)
│   ├── drift-monitor.sh        # Cron-mode drift detection
│   ├── update-rules.sh         # Self-update check library
│   └── report.sh               # Generate formatted reports
├── references/
│   ├── checks-os.md            # OS-level check documentation
│   ├── checks-openclaw.md      # OpenClaw-specific checks (THE MOAT)
│   ├── remediation-playbooks.md # Fix procedures with rollback
│   └── threat-feed.md          # Known CVEs + emerging threats
└── assets/
    └── baseline-rules.json     # Versioned rule definitions
```

## Check Library

### Tier 1: FREE (Baseline) — 25+ checks

**OS Hardening (existing 18 + additions):**
- SSH: password auth disabled, root login disabled, key-only, idle timeout
- Firewall: enabled, default deny inbound, minimal open ports
- Updates: security updates pending, auto-update status
- Permissions: world-writable files, SUID binaries, /tmp permissions
- Network: open ports audit, unnecessary services, IPv6 exposure
- Users: passwordless accounts, sudo without password, stale accounts
- Disk: encryption status (FileVault/LUKS/BitLocker)

**Basic OpenClaw:**
- Gateway running and bound correctly
- Gateway auth token set (not default/empty)
- Config file permissions (not world-readable)

**Output:** A-F grade, plain text report, actionable recommendations.

### Tier 2: PRO ($19/mo) — 40+ checks

**Everything in Free, plus:**

**Advanced OS:**
- Kernel hardening parameters (sysctl)
- Log rotation and audit logging enabled
- Fail2ban / rate limiting on SSH
- DNS leak checks
- TLS certificate expiry on exposed services
- Rootkit detection (rkhunter/chkrootkit patterns)

**OpenClaw-Specific (THE MOAT — nobody else builds these):**
- **Gateway auth:** Token strength, rotation age, binding config
- **Model allowlist:** Are unrestricted models exposed? Overly permissive?
- **Cron job audit:** Permissions, elevated flags, command injection vectors
- **Plugin/skill sandboxing:** Skills with exec access, unconstrained file access
- **Config exposure:** Sensitive fields in config (API keys, tokens) — are they env-var sourced or hardcoded?
- **Webhook security:** Inbound webhook auth, replay protection
- **Session security:** Session key entropy, expiry policy
- **Agent permissions:** Which agents have elevated access? Is it justified?
- **Browser profile security:** Stored credentials in managed browser profiles
- **Memory file exposure:** Are MEMORY.md files accessible outside intended scope?
- **Network binding:** Gateway bound to 0.0.0.0 vs localhost vs LAN — risk assessment
- **Update status:** Running outdated OpenClaw version with known vulnerabilities
- **Skill provenance:** Installed skills — source verification, tampering detection

**Output:** Detailed JSON report, severity scoring (CVSS-style), trend tracking.

### Tier 3: MANAGED ($49/mo) — Continuous + Remediation

**Everything in Pro, plus:**

- **Auto-remediation:** Safe fixes applied automatically with rollback snapshots
- **Drift monitoring:** Cron-based, alerts on regression from last-known-good state
- **Continuous scanning:** Configurable schedule (hourly/daily/weekly)
- **Alert routing:** Push notifications via Telegram, Discord, Slack, email
- **Baseline locking:** Define your target posture, get alerted on any deviation
- **Remediation playbooks:** Step-by-step fixes for every finding, with rollback
- **Monthly security digest:** Summary of posture changes, new threats, actions taken

---

## Self-Updating Mechanism

### Rule Versioning
```json
// assets/baseline-rules.json
{
  "version": "1.3.0",
  "updated": "2026-03-15",
  "checks": [
    {
      "id": "SSH-001",
      "name": "Password authentication disabled",
      "category": "os",
      "tier": "free",
      "severity": "high",
      "command": "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config",
      "expected": "PasswordAuthentication no",
      "remediation": "remediate.sh ssh-password-auth",
      "added": "1.0.0"
    },
    {
      "id": "OC-001",
      "name": "Gateway auth token set",
      "category": "openclaw",
      "tier": "free",
      "severity": "critical",
      "command": "openclaw status --json | jq '.gateway.authEnabled'",
      "expected": "true",
      "remediation": "remediate.sh oc-gateway-auth",
      "added": "1.0.0"
    }
  ]
}
```

### Update Flow
1. `update-rules.sh` checks a hosted rules endpoint (GitHub raw or ClawHub CDN)
2. Compares local `version` to remote `version`
3. Downloads new rules, validates checksum
4. Merges into local rule set (never deletes user-customized rules)
5. Logs update to `~/.clawscan/update-log.json`

### Update Sources (in priority order)
1. **ClawHub skill update** — `openclaw skill update clawscan`
2. **GitHub releases** — tagged rule bundles
3. **Community contributions** — PR-based new checks, reviewed before merge

---

## Drift Monitoring (Cron Mode)

### How It Works
```bash
# drift-monitor.sh
# 1. Load last baseline snapshot (~/.clawscan/baseline.json)
# 2. Run full scan
# 3. Diff against baseline
# 4. If regressions found:
#    a. Tier FREE/PRO: Generate alert message
#    b. Tier MANAGED: Auto-remediate safe fixes, alert on unsafe ones
# 5. Update baseline with current state
# 6. Route alerts via OpenClaw messaging
```

### Cron Setup (via OpenClaw)
```bash
# Daily scan at 3 AM
openclaw cron add --name "clawscan:daily-audit" \
  --schedule "0 3 * * *" \
  --prompt "Run ClawScan drift monitor: exec scripts/drift-monitor.sh"

# Hourly for managed tier
openclaw cron add --name "clawscan:hourly-monitor" \
  --schedule "0 * * * *" \
  --prompt "Run ClawScan drift monitor (managed): exec scripts/drift-monitor.sh --managed"
```

---

## Auto-Remediation Engine

### Safety Classification
Every remediation is classified:

| Safety Level | Action | Example |
|---|---|---|
| **SAFE** | Auto-fix, log, notify | Tighten file permissions, disable password auth |
| **MODERATE** | Fix with rollback snapshot | Firewall rule changes, SSH config changes |
| **DANGEROUS** | Alert only, never auto-fix | Removing users, changing network config, kernel params |

### Rollback System
```bash
# Before any remediation:
# 1. Snapshot affected files → ~/.clawscan/rollbacks/<timestamp>/
# 2. Apply fix
# 3. Verify fix worked (re-run check)
# 4. If verification fails → auto-rollback
# 5. Log everything to ~/.clawscan/remediation-log.json
```

### Remediation Examples
```bash
# remediate.sh ssh-password-auth
# 1. cp /etc/ssh/sshd_config ~/.clawscan/rollbacks/$(date +%s)/sshd_config
# 2. sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
# 3. Verify: grep '^PasswordAuthentication no' /etc/ssh/sshd_config
# 4. systemctl reload sshd (if running)
# 5. Log success/failure

# remediate.sh oc-gateway-auth
# 1. Generate strong token: openssl rand -hex 32
# 2. openclaw config apply gateway.auth.token=<token>
# 3. Verify: openclaw status --json | jq '.gateway.authEnabled'
# 4. Output token for user to save
```

---

## Alerting Integration

### Alert Routing
```bash
# Uses OpenClaw's native messaging — no extra config needed
# User sets preferred channel in ~/.clawscan/config.json:
{
  "alertChannel": "telegram",    # or discord, slack, email
  "alertLevel": "high",          # minimum severity to alert on
  "quietHours": ["23:00", "07:00"],
  "digestMode": "daily"          # or "immediate" or "weekly"
}
```

### Alert Format
```
🔴 ClawScan Alert — 2 regressions detected

CRITICAL: Gateway auth token not set (OC-001)
→ Auto-fixed: Token generated and applied

HIGH: SSH password auth re-enabled (SSH-001)
→ Auto-fixed: Disabled, sshd reloaded

Current Grade: B+ (was A-)
Next scan: 2026-03-15 03:00
```

---

## Monetization & Licensing

### How Tiers Work in a Skill

```json
// In SKILL.md frontmatter or config
{
  "pricing": {
    "free": { "checks": "baseline", "features": ["scan", "report"] },
    "pro": { "price": "$19/mo", "checks": "all", "features": ["scan", "report", "json-export", "trend-tracking", "openclaw-checks"] },
    "managed": { "price": "$49/mo", "checks": "all", "features": ["everything-pro", "auto-remediation", "drift-monitoring", "alerting", "monthly-digest"] }
  }
}
```

### Licensing Approach
- **Free tier:** Full source, runs locally, no license check
- **Pro/Managed:** License key validated against ClawHub API
- Key stored in `~/.clawscan/license.json`
- Offline grace period: 7 days
- **No phone-home telemetry** — just license validation

### Revenue Projections (Conservative)
- Month 1-2: 50 free users, 5 Pro ($95/mo)
- Month 3-4: 200 free, 15 Pro, 3 Managed ($432/mo)
- Month 6: 500 free, 40 Pro, 10 Managed ($1,260/mo) ← **$1K target**
- Month 12: 2,000 free, 100 Pro, 25 Managed ($3,125/mo)

Key assumption: OpenClaw user base grows. ClawScan grows with it as the default security answer.

---

## Tech Stack

### Core: Bash Only (Zero Dependencies)
- All scanning: bash + standard Unix tools (grep, awk, sed, ss, lsof, jq)
- jq is the only "nice-to-have" — fallback to grep/awk if missing
- Report generation: bash templating
- Rule parsing: jq on JSON rule files

### Why Not Python?
- Zero-dep install is the killer feature
- Works on any Unix system out of the box
- No virtualenv, no pip, no version conflicts
- Keeps the skill lightweight and fast

### Data Storage
- `~/.clawscan/` — all local state
- `baseline.json` — last-known-good posture
- `history/` — scan history for trend tracking
- `rollbacks/` — remediation snapshots
- `config.json` — user preferences
- `license.json` — Pro/Managed key

---

## Competitive Positioning

### Why ClawScan Wins on ClawHub

1. **Only OpenClaw-native security tool.** Nobody else is building checks for gateway auth, cron permissions, skill sandboxing, model allowlists.

2. **Zero install friction.** `openclaw skill install clawscan` → done. No Docker, no Python, no config.

3. **Self-updating.** Rules evolve with the threat landscape. Buy once, stay current.

4. **Auto-remediation with rollback.** Not just "here's what's wrong" — "I fixed it, here's the receipt."

5. **Built by someone running OpenClaw in production.** Every check exists because we hit the problem first.

6. **Community flywheel.** Free tier creates awareness → Pro converts power users → Managed converts lazy admins. Open-source checks invite contributions.

### vs. Existing Healthcheck Skill
The built-in healthcheck skill is a **workflow guide** — it tells the agent how to harden a system through conversation. ClawScan is a **product** — deterministic scripts, versioned rules, continuous monitoring, auto-remediation. They're complementary: healthcheck is the consultant, ClawScan is the tool.

---

## Build Roadmap

### Weekend 1: Foundation (Ship Free Tier)
- [ ] Restructure existing 18 checks into `baseline-rules.json` format
- [ ] Write `scan.sh` — rule-driven scanner with A-F grading
- [ ] Write `report.sh` — clean text + JSON output
- [ ] Add 7 basic OpenClaw checks (gateway auth, binding, config perms, update status, model allowlist, cron audit, memory exposure)
- [ ] Write SKILL.md with proper frontmatter
- [ ] Test on Mac + Linux
- [ ] Publish free tier to ClawHub
- **Deliverable:** Working skill, 25+ checks, installable from ClawHub

### Weekend 2: Pro Tier + Self-Updating
- [ ] Add 15+ advanced checks (kernel hardening, rootkit patterns, TLS, DNS)
- [ ] Add full OpenClaw check suite (13 checks)
- [ ] Build `update-rules.sh` — GitHub-based rule updates
- [ ] Build license validation (ClawHub API or simple key check)
- [ ] JSON export + severity scoring
- [ ] Trend tracking (scan history comparison)
- [ ] Set up Stripe for Pro tier
- **Deliverable:** Pro tier live, 40+ checks, self-updating rules

### Weekend 3: Managed Tier + Continuous Monitoring
- [ ] Build `drift-monitor.sh` — baseline diffing + regression detection
- [ ] Build `remediate.sh` — auto-fix engine with rollback
- [ ] Safety classification for all remediations
- [ ] Alert routing via OpenClaw messaging
- [ ] Cron setup helpers
- [ ] Monthly digest generator
- [ ] Managed tier licensing
- **Deliverable:** Full product live. Free/Pro/Managed all shipping.

### Ongoing
- [ ] Community check contributions (PR workflow)
- [ ] CVE tracking integration
- [ ] Cross-platform improvements (Windows/WSL)
- [ ] ClawHub analytics (install counts, conversion tracking)
- [ ] @UngratefulAI launch thread

---

## Kill the Standalone Site?

**Yes.** clawscan.app becomes a landing page / docs site only. The product IS the skill. The site drives awareness and hosts docs/pricing. All functionality lives in the skill.

- clawscan.app → marketing + docs + pricing
- ClawHub → distribution + install
- GitHub → source + community contributions
- Stripe → payment processing

---

## Open Questions

1. **ClawHub monetization support** — does ClawHub support paid skills yet? If not, we need our own license server or Stripe-direct.
2. **Rule update hosting** — GitHub raw files vs dedicated CDN vs ClawHub-managed updates
3. **Cross-platform** — macOS + Linux first. Windows/WSL later?
4. **Telemetry** — zero telemetry is a selling point, but we lose install/usage data. Worth it?
5. **Community governance** — who reviews contributed checks? Quality bar?
