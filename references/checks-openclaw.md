# OpenClaw-Specific Security Checks

These checks are unique to ClawScan — no other tool covers them.

## Free Tier

### OC-001: Config not world-readable
`openclaw.json` contains gateway auth tokens, API keys, and sensitive configuration. File permissions must restrict access to the owner only. Recommended: `chmod 600`.

### OC-002: Auth token strength
Gateway auth tokens should be at least 16 characters. Short tokens are brute-forceable. Generate strong tokens with `openssl rand -hex 32`.

### OC-003: Cron job security
Audits cron jobs for:
- `elevated: true` flag (runs with host privileges)
- Dangerous command patterns in prompts
- Unrestricted exec permissions per-job

Elevated cron jobs can modify system files, install software, and access protected resources.

### OC-004: Memory files protected
MEMORY.md and daily memory logs contain personal information, credentials, and operational details. These files must not be world-readable. Recommended: `chmod 600 MEMORY.md`.

### OC-005: Version up-to-date
Checks if the installed OpenClaw version matches the latest release. Outdated versions may have known vulnerabilities. Uses `openclaw update status` for comparison.

### OC-006: Workspace isolation
Verifies the workspace isn't in a shared directory (`/tmp`, `/public`, `/Users/Shared`). Shared directories allow other users to read and modify agent memory.

## Pro Tier (Coming Soon)

### OC-007: Session key entropy
Validates that session keys have sufficient randomness. Low-entropy keys can be predicted.

### OC-008: Agent elevated access audit
Maps which agents have elevated exec permissions and flags any without clear justification.

### OC-009: Skill provenance verification
Verifies installed skills haven't been tampered with by comparing checksums against the ClawHub registry.

### OC-010: Token rotation age
Tracks when gateway auth tokens were last rotated. Tokens older than 90 days are flagged.

### OC-011: Browser stored credentials
Scans managed browser profiles for stored passwords and session tokens that could be extracted.

### OC-012: Command injection vectors
Analyzes cron job prompts and skill scripts for potential command injection patterns.

### OC-013: Webhook replay protection
Checks if inbound webhooks implement timestamp validation and nonce checking to prevent replay attacks.
