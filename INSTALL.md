# ClawScan Installation Guide

## Quick Install

### Download and Run
```bash
# Download the latest release
curl -L https://github.com/osmankidwai-bot/clawscan/releases/latest/download/clawscan.py -o clawscan.py

# Make executable
chmod +x clawscan.py

# Scan your workspace
./clawscan.py
```

### Clone Repository
```bash
git clone https://github.com/osmankidwai-bot/clawscan.git
cd clawscan
./clawscan.py --help
```

## Requirements

- Python 3.7+ (no external dependencies required)
- Unix-like system (macOS, Linux, WSL on Windows)
- Read access to the directories you want to scan

## Usage Examples

### Basic Scanning
```bash
# Scan current directory
./clawscan.py

# Scan specific workspace
./clawscan.py --workspace ~/.openclaw/workspace

# Scan with JSON output for automation
./clawscan.py --json > security-report.json
```

### CI/CD Integration

#### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Run ClawScan
      run: |
        curl -L https://github.com/osmankidwai-bot/clawscan/releases/latest/download/clawscan.py -o clawscan.py
        chmod +x clawscan.py
        ./clawscan.py --json > security-report.json
    - name: Upload Security Report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: security-report.json
```

#### GitLab CI
```yaml
security_scan:
  stage: test
  script:
    - curl -L https://github.com/osmankidwai-bot/clawscan/releases/latest/download/clawscan.py -o clawscan.py
    - chmod +x clawscan.py
    - ./clawscan.py --json
  artifacts:
    reports:
      security: security-report.json
```

## Configuration

### Custom Rule Sets
ClawScan includes 35+ built-in security checks, but you can extend it with custom rules by modifying `security-checks.json`.

### Environment Variables
- `CLAWSCAN_CONFIG_PATH`: Path to custom configuration file
- `CLAWSCAN_VERBOSE`: Enable verbose logging
- `CLAWSCAN_NO_COLOR`: Disable colored output

## Enterprise Features

### Advanced Threat Intelligence (Pro)
- Integration with threat intelligence feeds
- Custom IOC matching
- Advanced behavioral analysis
- Enterprise reporting dashboard

### Integration Options
- SIEM integration via JSON output
- Webhook notifications for critical findings  
- API endpoints for programmatic scanning
- Custom remediation playbooks

## Support

- **Documentation**: [https://clawscan.app/docs](https://clawscan.app/docs)
- **Issues**: [GitHub Issues](https://github.com/osmankidwai-bot/clawscan/issues)
- **Security Reports**: security@clawscan.app
- **Enterprise Support**: enterprise@clawscan.app

## License

MIT License - see [LICENSE](LICENSE) file for details.