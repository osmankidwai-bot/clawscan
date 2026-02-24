# ClawScan v1.5 — Enterprise-Grade Security Scanner

**Addresses all major criticisms from v1.0:**

## What's New in v1.5

### 🔥 **35+ Security Checks** (was 18)
- **AI Agent Specific**: Prompt injection, tool chain poisoning, agent memory attacks
- **Credential Detection**: API keys, AWS credentials, private keys, JWT tokens  
- **Network Threats**: Reverse shells, DNS tunneling, Tor usage
- **Privilege Escalation**: Sudo abuse, file permissions, service manipulation
- **Code Injection**: Python/Shell injection, SQL injection patterns
- **Persistence**: Hidden files, SSH key manipulation, autostart abuse

### 🧠 **Behavioral Monitoring** (not just grep)
- Monitors actual process execution
- Tracks file system changes
- Detects network connections
- Real-time threat detection during agent execution

### 📊 **Weighted Risk Scoring** 
- **CRITICAL** (weight 10): Immediate security threats
- **HIGH** (weight 7): Significant vulnerabilities  
- **MEDIUM** (weight 4): Moderate risks
- **LOW** (weight 2): Minor issues
- **INFO** (weight 1): Informational findings

### 🎯 **AI Agent Threat Focus**
- Prompt injection detection (role hijacking, data exfiltration)
- Tool chain security analysis
- Agent memory poisoning detection
- Session hijacking prevention
- Model extraction attempt detection

## Usage

```bash
# Scan current directory
./clawscan.py

# Scan specific workspace
./clawscan.py --workspace ~/.openclaw/workspace

# JSON output for automation
./clawscan.py --json

# Version info
./clawscan.py --version
```

## Output Example

```
╔══════════════════════════════════════════════╗
║          ClawScan v1.5.0 Security Report     ║
╠══════════════════════════════════════════════╣
║  Grade: A- (87/100)                          ║
╠══════════════════════════════════════════════╣
║  Top Security Issues:                        ║
║  HIGH: Hardcoded API Keys                    ║
║  MEDIUM: Package Installation                ║
║  LOW: Unicode Obfuscation                    ║
╠══════════════════════════════════════════════╣
║  Enhanced v1.5: 35+ checks • Behavioral     ║
║  monitoring • AI threat focus • Open source ║
╚══════════════════════════════════════════════╝
```

## Why v1.5?

**Developer feedback on v1.0:**
- "Only 18 checks? My IDE has more" → **35+ comprehensive checks**
- "Grep-based detection is trivial" → **Behavioral monitoring engine**  
- "Grading seems arbitrary" → **Weighted severity scoring**
- "Missing real AI threats" → **AI agent-specific threat detection**
- "No plugin architecture" → **Dynamic SecurityCheck rule engine**

## Design Principles (Dieter Rams)

- **Useful**: Detects real threats, not textbook vulnerabilities
- **Understandable**: Clear categories, actionable descriptions
- **Unobtrusive**: Fast execution, minimal false positives
- **Thorough**: Complete AI agent attack surface coverage
- **Minimal**: Single command, clear output, zero dependencies

## License

Open Source - because security tools should be transparent and community-driven.

---

**ClawScan v1.5: From weekend hack to enterprise-grade security platform.** ✅