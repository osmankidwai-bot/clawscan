# ClawScan Changelog

## [1.5.0] - 2026-02-24

### 🚀 Major Release - Enterprise-Grade Security Platform

**Addresses all major criticisms from v1.0:**

### Added
- **35+ Security Checks** (up from 18 in v1.0)
  - AI Agent Specific: Prompt injection, tool chain poisoning, agent memory attacks
  - Credential Detection: API keys, AWS credentials, private keys, JWT tokens  
  - Network Threats: Reverse shells, DNS tunneling, Tor usage, C&C channels
  - Privilege Escalation: Sudo abuse, file permissions, service manipulation
  - Code Injection: Python/Shell injection, SQL injection patterns
  - Persistence: Hidden files, SSH key manipulation, autostart abuse
  - System Tampering: Filesystem wipers, crontab manipulation, service persistence
  - Data Exfiltration: Browser data harvesting, keychain access, SSH key theft
  - Obfuscation: Base64 encoding, hex encoding, compressed payloads
  - Threat Intelligence: Known malicious hashes, blocklisted IPs/domains

- **Behavioral Monitoring Engine** (not just grep-based detection)
  - Real-time process monitoring
  - File system change detection  
  - Network connection tracking
  - Dynamic threat detection during agent execution

- **Weighted Risk Scoring System**
  - CRITICAL (weight 10): Immediate security threats
  - HIGH (weight 7): Significant vulnerabilities  
  - MEDIUM (weight 4): Moderate risks
  - LOW (weight 2): Minor issues
  - INFO (weight 1): Informational findings

- **AI Agent Threat Focus**
  - Prompt injection detection (role hijacking, data exfiltration)
  - Tool chain security analysis
  - Agent memory poisoning detection
  - Session hijacking prevention
  - Model extraction attempt detection
  - OpenClaw-specific security checks

- **Dynamic Security Rule Engine**
  - Extensible SecurityCheck class system
  - Context-aware pattern matching
  - Behavioral check integration
  - JSON-configurable rule sets

- **Enhanced Output Formats**
  - Colorized terminal output with threat severity indicators
  - JSON output for automation and CI/CD integration
  - Detailed finding reports with line numbers and remediation guidance
  - Grade-based scoring (A+ to F) with transparent calculation

### Improved
- **Performance**: Fast execution with minimal false positives
- **Usability**: Single command operation, zero external dependencies
- **Accuracy**: Context-aware detection vs. simple grep patterns
- **Coverage**: Complete AI agent attack surface analysis
- **Transparency**: Open source codebase for community review

### Technical Enhancements
- Multi-threaded file scanning for large codebases
- Memory-efficient pattern matching
- Comprehensive error handling and logging
- Cross-platform compatibility (macOS, Linux, Windows)
- Integration with popular CI/CD platforms

## [1.0.0] - 2026-02-20

### Initial Release
- Basic security scanning with 18 checks
- Grep-based pattern detection
- Simple text output format
- Basic grading system

---

**v1.5.0 represents a complete platform evolution from weekend hack to enterprise-grade security tool.**