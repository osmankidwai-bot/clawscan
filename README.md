# ClawScan Security

The definitive security scanner for OpenClaw deployments. Pure bash, zero dependencies, 25+ checks.

## Install

```bash
openclaw skill install clawscan
```

Or clone and run directly:

```bash
git clone https://github.com/osmankidwai-bot/clawscan.git
cd clawscan/scripts
./scan.sh
```

## Usage

```bash
# Basic scan (failures only)
./scripts/scan.sh

# Verbose (all checks)
./scripts/scan.sh --verbose

# JSON output
./scripts/scan.sh --json

# Custom path
./scripts/scan.sh --path /your/openclaw/dir
```

## What It Checks

| Category | Checks | Max Points |
|---|---|---|
| Config Security | 7 | 40 |
| File Exposure | 4 | 25 |
| Skill Security | 4 | 20 |
| Network Security | 3 | 15 |
| OpenClaw-Specific | 6 | 30 |
| **Total** | **24** | **130** |

### Grading

| Grade | Score |
|---|---|
| A | 90%+ |
| B+ | 80%+ |
| B | 70%+ |
| C+ | 60%+ |
| C | 50%+ |
| D | 30%+ |
| F | <30% |

## Tiers

- **Free:** 24 checks, A-F grading, text + JSON output
- **Pro ($19/mo):** 40+ checks, trend tracking, severity scoring — coming soon
- **Managed ($49/mo):** Continuous monitoring, auto-remediation, alerting — coming soon

## Requirements

- bash 4+
- Standard Unix tools (grep, awk, sed, stat, find)
- jq (optional, graceful fallback)
- Works on macOS and Linux

## License

MIT
