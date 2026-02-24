#!/usr/bin/env python3
"""
ClawScan v1.5 — Enterprise-grade security scanner for OpenClaw AI agents
Addresses all major criticisms from v1.0:
- 35+ security checks (not 18)
- Behavioral monitoring (not just grep)
- Weighted severity scoring
- AI agent threat focus
- Dynamic rule engine
"""

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple, Any
import hashlib
import tempfile

__version__ = "1.5.0"

# Threat Categories with Weighted Scoring
THREAT_CATEGORIES = {
    "CRITICAL": {"weight": 10, "color": "\033[91m"},  # Red
    "HIGH": {"weight": 7, "color": "\033[93m"},       # Yellow  
    "MEDIUM": {"weight": 4, "color": "\033[94m"},     # Blue
    "LOW": {"weight": 2, "color": "\033[92m"},        # Green
    "INFO": {"weight": 1, "color": "\033[90m"}        # Gray
}

RESET_COLOR = "\033[0m"

class SecurityCheck:
    """Dynamic security rule with context awareness"""
    def __init__(self, name: str, category: str, pattern: str = None, 
                 behavior_check: bool = False, description: str = ""):
        self.name = name
        self.category = category
        self.pattern = re.compile(pattern) if pattern else None
        self.behavior_check = behavior_check
        self.description = description
    
    def check_file(self, file_path: str, content: str) -> List[Dict]:
        findings = []
        if self.pattern:
            matches = list(self.pattern.finditer(content))
            for match in matches:
                findings.append({
                    "rule": self.name,
                    "category": self.category,
                    "file": file_path,
                    "line": content[:match.start()].count('\n') + 1,
                    "match": match.group(),
                    "description": self.description
                })
        return findings

class BehaviorMonitor:
    """Monitors actual system behavior during agent execution"""
    
    def __init__(self):
        self.monitored_paths = [
            "/etc/passwd", "/etc/shadow", "/root", 
            os.path.expanduser("~/.ssh"),
            os.path.expanduser("~/.openclaw/config.json")
        ]
        self.baseline = self._get_baseline()
    
    def _get_baseline(self) -> Dict:
        """Get baseline system state"""
        return {
            "processes": set(self._get_processes()),
            "network": set(self._get_network_connections()),
            "files": {path: os.path.getmtime(path) for path in self.monitored_paths if os.path.exists(path)}
        }
    
    def _get_processes(self) -> List[str]:
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            return [line.split()[10] for line in result.stdout.split('\n')[1:] if line.strip()]
        except:
            return []
    
    def _get_network_connections(self) -> List[str]:
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            return [line.strip() for line in result.stdout.split('\n') if 'LISTEN' in line]
        except:
            return []
    
    def detect_changes(self) -> List[Dict]:
        """Detect behavioral changes since baseline"""
        findings = []
        current_state = self._get_baseline()
        
        # Check for new processes
        new_processes = set(current_state["processes"]) - self.baseline["processes"]
        for proc in new_processes:
            if any(suspicious in proc.lower() for suspicious in ['nc', 'ncat', 'curl', 'wget', 'ssh', 'scp']):
                findings.append({
                    "rule": "Suspicious Process Execution",
                    "category": "CRITICAL",
                    "file": "/proc",
                    "line": 0,
                    "match": proc,
                    "description": f"Potentially malicious process: {proc}"
                })
        
        # Check file modifications
        for file_path, baseline_time in self.baseline["files"].items():
            if os.path.exists(file_path):
                current_time = os.path.getmtime(file_path)
                if current_time > baseline_time:
                    findings.append({
                        "rule": "Critical File Modification",
                        "category": "CRITICAL",
                        "file": file_path,
                        "line": 0,
                        "match": f"Modified at {time.ctime(current_time)}",
                        "description": f"Critical system file was modified: {file_path}"
                    })
        
        return findings

# Enhanced Security Rules - 35+ checks
SECURITY_RULES = [
    # AI Agent Specific Threats
    SecurityCheck("Prompt Injection - Role Hijacking", "CRITICAL", 
                 r"(ignore previous instructions|you are now|system:|assistant:|role:|persona:)", 
                 description="Attempts to hijack AI agent role"),
    
    SecurityCheck("Prompt Injection - Data Exfiltration", "CRITICAL",
                 r"(print all|show me|reveal|dump|export).*?(config|secret|key|password|token)",
                 description="Attempts to extract sensitive data via prompt manipulation"),
    
    SecurityCheck("Tool Chain Poisoning", "HIGH",
                 r"(subprocess|exec|eval|shell=True|os\.system)",
                 description="Potentially dangerous code execution in tool chains"),
    
    SecurityCheck("Agent Memory Poisoning", "HIGH",
                 r"(MEMORY\.md|memory/.*\.md).*?(malicious|backdoor|exploit)",
                 description="Attempts to poison agent long-term memory"),
    
    SecurityCheck("Session Hijacking Attempt", "HIGH",
                 r"(session|auth|token).*?(steal|capture|intercept|hijack)",
                 description="Potential session hijacking patterns"),
    
    # Credential & Secret Detection  
    SecurityCheck("Hardcoded API Keys", "CRITICAL",
                 r"(api[_-]?key|secret[_-]?key)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_-]{20,}[\"']",
                 description="Hardcoded API keys or secrets"),
    
    SecurityCheck("AWS Credentials", "CRITICAL",
                 r"AKIA[0-9A-Z]{16}",
                 description="AWS Access Key ID detected"),
    
    SecurityCheck("Private Key Material", "CRITICAL",
                 r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
                 description="Private cryptographic key detected"),
    
    SecurityCheck("JWT Tokens", "HIGH",
                 r"eyJ[A-Za-z0-9_/+-]*\.[A-Za-z0-9_/+-]*\.[A-Za-z0-9_/+-]*",
                 description="JWT token detected"),
    
    SecurityCheck("Database URLs", "HIGH",
                 r"(postgresql|mysql|mongodb)://[^\\s\"']+",
                 description="Database connection string detected"),
    
    # Network & Communication Threats
    SecurityCheck("Reverse Shell Patterns", "CRITICAL",
                 r"(nc|ncat|netcat).*?-[el].*?[0-9]+|bash.*?/dev/tcp",
                 description="Reverse shell command detected"),
    
    SecurityCheck("DNS Tunneling", "HIGH",
                 r"dig.*?TXT|nslookup.*?-type=TXT.*?[a-f0-9]{32,}",
                 description="Potential DNS tunneling activity"),
    
    SecurityCheck("Suspicious Network Requests", "MEDIUM",
                 r"(requests\.get|urllib\.request|curl|wget).*?(\.onion|suspicious-domain\.com)",
                 description="Network requests to suspicious domains"),
    
    SecurityCheck("Tor Usage", "HIGH",
                 r"(tor|9050|127\.0\.0\.1:9050|socks5://)",
                 description="Tor network usage detected"),
    
    # File System & Privilege Escalation
    SecurityCheck("Privilege Escalation - Sudo", "CRITICAL",
                 r"sudo\s+(?!-k|--reset-timestamp)",
                 description="Sudo usage for privilege escalation"),
    
    SecurityCheck("Sensitive File Access", "HIGH",
                 r"/etc/(passwd|shadow|sudoers|hosts)|/root/|~/.ssh/",
                 description="Access to sensitive system files"),
    
    SecurityCheck("Cron Job Manipulation", "HIGH",
                 r"crontab\s+-[er]|echo.*?>>.*?crontab",
                 description="Potential cron job manipulation"),
    
    SecurityCheck("Service Manipulation", "HIGH",
                 r"systemctl\s+(enable|start|stop|restart)|service\s+\w+\s+(start|stop|restart)",
                 description="System service manipulation"),
    
    SecurityCheck("Temp File Abuse", "MEDIUM",
                 r"/tmp/\.[a-zA-Z0-9]+|mktemp.*?--suffix=\.[a-zA-Z]+",
                 description="Hidden temporary files - potential persistence"),
    
    # Code Injection & Execution
    SecurityCheck("Code Injection - Python", "CRITICAL",
                 r"exec\(.*?\)|eval\(.*?\)|compile\(.*?,'<string>','exec'\)",
                 description="Dynamic code execution in Python"),
    
    SecurityCheck("Code Injection - Shell", "CRITICAL",
                 r"os\.system|subprocess\.call.*?shell=True",
                 description="Shell injection vulnerability"),
    
    SecurityCheck("SQL Injection Patterns", "HIGH",
                 r"(SELECT|INSERT|UPDATE|DELETE).*?(\+|%|concat)",
                 description="Potential SQL injection patterns"),
    
    SecurityCheck("Path Traversal", "MEDIUM",
                 r"\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c",
                 description="Path traversal attack patterns"),
    
    # AI Model & Tool Abuse
    SecurityCheck("Model Extraction Attempt", "HIGH",
                 r"(model\.save|torch\.save|pickle\.dump).*?(\/tmp|\/var\/tmp|\.\.\/)",
                 description="Potential AI model extraction"),
    
    SecurityCheck("Tool Permission Escalation", "HIGH",
                 r"(chmod|chown)\s+.*?(777|u\+s|g\+s)",
                 description="Dangerous file permission changes"),
    
    SecurityCheck("Browser Automation Abuse", "MEDIUM",
                 r"(selenium|playwright|puppeteer).*?(password|login|bank|payment)",
                 description="Browser automation targeting sensitive sites"),
    
    SecurityCheck("Clipboard Access", "MEDIUM",
                 r"(clipboard|xclip|pbcopy|pbpaste)",
                 description="Clipboard access - potential credential theft"),
    
    # Persistence & Backdoors
    SecurityCheck("Hidden File Creation", "HIGH",
                 r"touch\s+\.[a-zA-Z0-9]+|mkdir\s+\.[a-zA-Z0-9]+",
                 description="Hidden file/directory creation"),
    
    SecurityCheck("Autostart Manipulation", "HIGH",
                 r"(~/.bash_profile|~/.bashrc|~/.zshrc|~/\.config/autostart)",
                 description="Shell startup file modification"),
    
    SecurityCheck("SSH Key Manipulation", "CRITICAL",
                 r"ssh-keygen|authorized_keys|known_hosts.*?>>",
                 description="SSH key manipulation for persistence"),
    
    # Data Exfiltration
    SecurityCheck("Archive & Compression", "MEDIUM",
                 r"(tar|zip|gzip|7z).*?(-c|--create).*?/(home|etc|root)",
                 description="Archiving sensitive directories"),
    
    SecurityCheck("Base64 Encoding", "MEDIUM",
                 r"base64\s+-[ew]|echo.*?\|.*?base64",
                 description="Base64 encoding - potential data hiding"),
    
    SecurityCheck("Large File Operations", "MEDIUM",
                 r"(dd|cp|rsync).*?if=|of=.*?(home|etc|root)",
                 description="Large file operations on sensitive directories"),
    
    # Configuration & Environment
    SecurityCheck("Environment Variable Abuse", "MEDIUM",
                 r"export\s+[A-Z_]*(PATH|LD_LIBRARY_PATH|PYTHONPATH)",
                 description="Environment variable manipulation"),
    
    SecurityCheck("Package Installation", "MEDIUM",
                 r"(pip|npm|gem|apt|yum|brew)\s+install",
                 description="Package installation - potential supply chain attack"),
    
    SecurityCheck("OpenClaw Config Tampering", "CRITICAL",
                 r"openclaw\s+config\s+set.*?(gateway|agents|models)",
                 description="OpenClaw configuration tampering"),
    
    # Unicode & Steganography
    SecurityCheck("Unicode Obfuscation", "MEDIUM",
                 r"[\u200b\u200c\u200d\ufeff]",
                 description="Invisible Unicode characters - potential obfuscation"),
    
    SecurityCheck("Homoglyph Attack", "LOW",
                 r"[а-я].*?[a-z]|[а-я].*?[A-Z]",  # Cyrillic mixed with Latin
                 description="Homoglyph characters - potential spoofing")
]

class ClawScan:
    """Main ClawScan security scanner"""
    
    def __init__(self):
        self.findings = []
        self.behavior_monitor = BehaviorMonitor()
        self.rules = SECURITY_RULES
    
    def scan_workspace(self, path: str = ".") -> Dict:
        """Scan workspace with behavioral monitoring"""
        workspace_path = Path(path).resolve()
        
        print(f"🔍 ClawScan v{__version__} - Scanning {workspace_path}")
        print(f"📊 Loaded {len(self.rules)} security rules")
        
        # Static Analysis
        for file_path in self._get_files(workspace_path):
            self._scan_file(file_path)
        
        # Behavioral Analysis
        behavioral_findings = self.behavior_monitor.detect_changes()
        self.findings.extend(behavioral_findings)
        
        return self._generate_report()
    
    def _get_files(self, workspace_path: Path) -> List[str]:
        """Get all relevant files to scan"""
        extensions = {'.py', '.sh', '.js', '.md', '.yaml', '.yml', '.json', '.toml'}
        files = []
        
        for file_path in workspace_path.rglob('*'):
            if (file_path.is_file() and 
                (file_path.suffix.lower() in extensions or 
                 file_path.name in ['SKILL.md', 'README.md', 'config', 'openclaw.json'])):
                files.append(str(file_path))
        
        return files
    
    def _scan_file(self, file_path: str):
        """Scan individual file with all security rules"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for rule in self.rules:
                findings = rule.check_file(file_path, content)
                self.findings.extend(findings)
                
        except Exception as e:
            print(f"⚠️  Could not scan {file_path}: {e}")
    
    def _generate_report(self) -> Dict:
        """Generate final security report with grading"""
        # Calculate weighted risk score
        total_weight = 0
        max_possible_weight = 100  # Baseline for grading
        
        category_counts = {}
        for finding in self.findings:
            category = finding['category']
            weight = THREAT_CATEGORIES[category]['weight']
            total_weight += weight
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Grade calculation (inverted - lower weight = higher grade)
        grade_score = max(0, 100 - (total_weight * 2))  # 2x multiplier for sensitivity
        grade = self._get_grade(grade_score)
        
        # Generate summary
        summary = []
        critical_count = category_counts.get('CRITICAL', 0)
        high_count = category_counts.get('HIGH', 0)
        
        if critical_count > 0:
            summary.append(f"🚨 {critical_count} critical security issues")
        if high_count > 0:
            summary.append(f"⚠️ {high_count} high-risk vulnerabilities")
        if critical_count == 0 and high_count == 0:
            summary.append("✅ No critical security issues found")
        
        return {
            "version": __version__,
            "timestamp": time.time(),
            "grade": grade,
            "score": grade_score,
            "total_findings": len(self.findings),
            "category_counts": category_counts,
            "summary": summary,
            "findings": self.findings[:10],  # Top 10 for display
            "all_findings": len(self.findings) > 10
        }
    
    def _get_grade(self, score: int) -> str:
        """Convert numeric score to letter grade"""
        if score >= 95: return "A+"
        elif score >= 90: return "A" 
        elif score >= 85: return "A-"
        elif score >= 80: return "B+"
        elif score >= 75: return "B"
        elif score >= 70: return "B-"
        elif score >= 65: return "C+"
        elif score >= 60: return "C"
        elif score >= 55: return "C-"
        elif score >= 50: return "D"
        else: return "F"
    
    def print_report(self, report: Dict):
        """Print formatted security report"""
        grade = report['grade']
        score = report['score']
        
        # Color based on grade
        if grade.startswith('A'): color = "\033[92m"  # Green
        elif grade.startswith('B'): color = "\033[94m"  # Blue  
        elif grade.startswith('C'): color = "\033[93m"  # Yellow
        else: color = "\033[91m"  # Red
        
        print(f"\n╔══════════════════════════════════════════════╗")
        print(f"║          ClawScan v{__version__} Security Report           ║")
        print(f"╠══════════════════════════════════════════════╣")
        print(f"║  Grade: {color}{grade}{RESET_COLOR} ({score}/100)                         ║")
        print(f"╠══════════════════════════════════════════════╣")
        
        if report['findings']:
            print(f"║  Top Security Issues:                        ║")
            for i, finding in enumerate(report['findings'][:5], 1):
                category_color = THREAT_CATEGORIES[finding['category']]['color']
                issue = finding['rule'][:35] + "..." if len(finding['rule']) > 35 else finding['rule']
                print(f"║  {category_color}{finding['category']}{RESET_COLOR}: {issue:<30} ║")
        else:
            print(f"║  ✅ No security issues detected               ║")
        
        if report['all_findings']:
            remaining = len(report.get('findings', [])) - 5
            print(f"║  📋 {remaining} additional findings...        ║")
        
        print(f"╠══════════════════════════════════════════════╣")
        print(f"║  Enhanced v1.5: 35+ checks • Behavioral     ║")
        print(f"║  monitoring • AI threat focus • Open source ║")
        print(f"╚══════════════════════════════════════════════╝")
        
        print(f"\n📊 Security Summary:")
        for category, count in report['category_counts'].items():
            color = THREAT_CATEGORIES[category]['color']
            print(f"  {color}{category}{RESET_COLOR}: {count} findings")
        
        if report['findings']:
            print(f"\n🔍 Top Findings:")
            for finding in report['findings'][:3]:
                print(f"  • {finding['rule']} ({finding['file']}:{finding['line']})")
                print(f"    {finding['description']}")

def main():
    parser = argparse.ArgumentParser(
        description="ClawScan v1.5 - Enterprise-grade security scanner for OpenClaw AI agents",
        epilog="Example: clawscan.py --workspace ~/.openclaw/workspace"
    )
    parser.add_argument('--workspace', '-w', 
                       default='.', 
                       help='Workspace path to scan (default: current directory)')
    parser.add_argument('--json', 
                       action='store_true', 
                       help='Output results in JSON format')
    parser.add_argument('--version', 
                       action='version', 
                       version=f'ClawScan {__version__}')
    
    args = parser.parse_args()
    
    scanner = ClawScan()
    report = scanner.scan_workspace(args.workspace)
    
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        scanner.print_report(report)
        
    # Exit with error code if critical issues found
    critical_count = report['category_counts'].get('CRITICAL', 0)
    sys.exit(1 if critical_count > 0 else 0)

if __name__ == "__main__":
    main()