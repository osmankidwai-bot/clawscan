# OS-Level Security Checks

## Config Security

### CFG-001: Config file exists
Verifies `openclaw.json` exists and is valid JSON. Without a config, gateway runs with defaults which may not be secure.

### CFG-002: No hardcoded API keys
Scans config for common API key patterns (OpenAI `sk-`, AWS `AKIA`, GitHub `ghp_`/`gho_`, Slack `xox`, JWTs). Keys should be in environment variables, not config files.

### CFG-007: Exec security policy
Checks if exec security is set to `full` without an allowlist. `full` mode without restrictions allows arbitrary command execution.

## File Exposure

### FILE-001: No passwords in MEMORY.md
MEMORY.md often contains sensitive operational data. Scans for plaintext password/secret patterns. Use environment variables or a secret manager instead.

### FILE-002: No .env secrets
Searches workspace for `.env*` files containing API keys or passwords. These files are often accidentally committed to git.

### FILE-003: No private keys
Scans workspace for SSH/PGP private key files. Private keys should never be stored in the OpenClaw workspace.

### FILE-004: Workspace permissions
Verifies the workspace directory isn't world-readable. Other users on the system shouldn't be able to read agent memory and config.

## Skill Security

### SKILL-001: Skills from known sources
Checks installed skill manifests for source URLs. Skills from unknown sources may contain malicious code.

### SKILL-002: No exec override to full
Skills can override exec security policy. A skill setting `exec.security: "full"` can run arbitrary commands.

### SKILL-003: No unjustified elevated perms
Checks for skills requesting root/sudo/admin permissions without justification in their manifest.

### SKILL-004: Skills dir not world-writable
A world-writable skills directory allows any user to inject malicious skills.

## Network Security

### NET-001: Gateway not publicly exposed
Gateway bound to 0.0.0.0 or a public IP without auth allows anyone to connect and issue commands.

### NET-002: Webhooks use HTTPS
HTTP webhooks transmit data (including tokens) in plaintext. Always use HTTPS.

### NET-003: Browser cookies secured
Browser profile cookies should not be readable by other system users. Contains session tokens for logged-in services.
