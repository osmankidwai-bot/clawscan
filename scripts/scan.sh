#!/usr/bin/env bash
# ClawScan Security Scanner — Pure bash, zero dependencies
# https://clawscan.app
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="$SCRIPT_DIR/../assets/baseline-rules.json"

# Defaults
OC_PATH="${HOME}/.openclaw"
JSON_OUTPUT=false
VERBOSE=false
NO_COLOR=false

# Colors (disabled if NO_COLOR or not a terminal)
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "true" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' RESET=''
fi

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --path) OC_PATH="$2"; shift 2 ;;
        --json) JSON_OUTPUT=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        --no-color) NO_COLOR=true; RED='' GREEN='' YELLOW='' BLUE='' BOLD='' RESET=''; shift ;;
        --version) echo "clawscan $VERSION"; exit 0 ;;
        --help|-h) echo "Usage: scan.sh [--path DIR] [--json] [--verbose] [--no-color]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Verify path exists
if [[ ! -d "$OC_PATH" ]]; then
    echo "Error: OpenClaw directory not found at $OC_PATH"
    echo "Hint: Run with --path /your/openclaw/dir"
    exit 1
fi

# ── Helpers ──────────────────────────────────────────────────────────

TOTAL_SCORE=0
MAX_SCORE=0
RESULTS=()
FAIL_COUNT=0
PASS_COUNT=0

# JSON helper — parse a key from JSON without jq
json_get() {
    local file="$1" key="$2"
    if command -v jq &>/dev/null; then
        jq -r "$key // empty" "$file" 2>/dev/null || echo ""
    else
        # Fallback: grep-based (handles simple flat keys)
        grep -oP "\"${key#.}\"\\s*:\\s*\"?\\K[^\",$}]+" "$file" 2>/dev/null | head -1 || echo ""
    fi
}

# Deep JSON check — does a key path exist and have a truthy value?
json_has() {
    local file="$1" key="$2"
    if command -v jq &>/dev/null; then
        local val
        val=$(jq -r "$key // empty" "$file" 2>/dev/null)
        [[ -n "$val" && "$val" != "null" && "$val" != "false" ]]
    else
        grep -q "\"${key#.}\"" "$file" 2>/dev/null
    fi
}

record_result() {
    local category="$1" check_name="$2" passed="$3" points="$4" message="$5" severity="${6:-medium}"
    MAX_SCORE=$((MAX_SCORE + points))
    if [[ "$passed" == "true" ]]; then
        TOTAL_SCORE=$((TOTAL_SCORE + points))
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    RESULTS+=("${category}|${check_name}|${passed}|${points}|${message}|${severity}")
}

get_grade() {
    local score=$1
    if   (( score >= 90 )); then echo "A"
    elif (( score >= 80 )); then echo "B+"
    elif (( score >= 70 )); then echo "B"
    elif (( score >= 60 )); then echo "C+"
    elif (( score >= 50 )); then echo "C"
    elif (( score >= 30 )); then echo "D"
    else echo "F"
    fi
}

# ── Config Helpers ───────────────────────────────────────────────────

CONFIG_FILE="$OC_PATH/openclaw.json"
WORKSPACE="$OC_PATH/workspace"

config_exists() {
    [[ -f "$CONFIG_FILE" ]]
}

# ── CHECKS: Config Security (40 pts) ────────────────────────────────

check_config_exists() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        record_result "Config Security" "Config file exists" "false" 5 "openclaw.json not found" "high"
        return
    fi
    if command -v jq &>/dev/null; then
        if jq empty "$CONFIG_FILE" 2>/dev/null; then
            record_result "Config Security" "Config file exists" "true" 5 "openclaw.json exists and is valid JSON"
        else
            record_result "Config Security" "Config file exists" "false" 5 "openclaw.json exists but is not valid JSON" "high"
        fi
    elif python3 -c "import json; json.load(open('$CONFIG_FILE'))" 2>/dev/null; then
        record_result "Config Security" "Config file exists" "true" 5 "openclaw.json exists and is valid JSON"
    else
        record_result "Config Security" "Config file exists" "true" 5 "openclaw.json exists (could not validate JSON)"
    fi
}

check_no_hardcoded_keys() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        record_result "Config Security" "No hardcoded API keys" "true" 10 "No config file to check"
        return
    fi
    local content
    content=$(cat "$CONFIG_FILE" 2>/dev/null || echo "")
    # Check for common API key patterns
    if echo "$content" | grep -qE 'sk-[A-Za-z0-9]{20,}|key-[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|xox[bpas]-[A-Za-z0-9-]{10,}'; then
        record_result "Config Security" "No hardcoded API keys" "false" 10 "API keys/tokens found hardcoded in config" "critical"
    else
        record_result "Config Security" "No hardcoded API keys" "true" 10 "No hardcoded API keys in config"
    fi
}

check_gateway_auth() {
    if ! config_exists; then
        record_result "Config Security" "Gateway auth configured" "false" 5 "No config file" "high"
        return
    fi
    if json_has "$CONFIG_FILE" '.gateway.auth'; then
        record_result "Config Security" "Gateway auth configured" "true" 5 "Gateway auth is configured"
    elif json_has "$CONFIG_FILE" '.gateway.auth.token'; then
        record_result "Config Security" "Gateway auth configured" "true" 5 "Gateway auth token is set"
    else
        record_result "Config Security" "Gateway auth configured" "false" 5 "Gateway auth not configured" "critical"
    fi
}

check_gateway_bind() {
    if ! config_exists; then
        record_result "Config Security" "Gateway bind secure" "true" 5 "No config file (defaults to localhost)"
        return
    fi
    local bind
    bind=$(json_get "$CONFIG_FILE" '.gateway.bind' 2>/dev/null)
    local has_auth=false
    json_has "$CONFIG_FILE" '.gateway.auth' && has_auth=true

    if [[ "$bind" == "0.0.0.0" && "$has_auth" == "false" ]]; then
        record_result "Config Security" "Gateway bind secure" "false" 5 "Gateway bound to 0.0.0.0 without auth" "critical"
    else
        record_result "Config Security" "Gateway bind secure" "true" 5 "Gateway bind is secure"
    fi
}

check_https_configured() {
    if ! config_exists; then
        record_result "Config Security" "HTTPS/TLS configured" "true" 5 "No config (local-only is fine)"
        return
    fi
    local bind
    bind=$(json_get "$CONFIG_FILE" '.gateway.bind' 2>/dev/null)
    local has_tls=false
    json_has "$CONFIG_FILE" '.gateway.tls' && has_tls=true
    json_has "$CONFIG_FILE" '.gateway.https' && has_tls=true
    json_has "$CONFIG_FILE" '.gateway.ssl' && has_tls=true

    if [[ "$bind" != "127.0.0.1" && "$bind" != "localhost" && "$bind" != "::1" && "$bind" != "" && "$has_tls" == "false" ]]; then
        record_result "Config Security" "HTTPS/TLS configured" "false" 5 "No HTTPS/TLS for remote gateway access" "high"
    else
        record_result "Config Security" "HTTPS/TLS configured" "true" 5 "HTTPS/TLS configured or not needed"
    fi
}

check_model_allowlist() {
    if ! config_exists; then
        record_result "Config Security" "Model allowlist set" "false" 5 "No config file" "medium"
        return
    fi
    if command -v jq &>/dev/null; then
        local models
        models=$(jq -r '.agents.defaults.models // empty' "$CONFIG_FILE" 2>/dev/null)
        if [[ -n "$models" && "$models" != "*" && "$models" != '["*"]' && "$models" != "null" ]]; then
            record_result "Config Security" "Model allowlist set" "true" 5 "Model allowlist is configured"
        else
            record_result "Config Security" "Model allowlist set" "false" 5 "No model allowlist (any model can be used)" "medium"
        fi
    else
        if grep -q '"models"' "$CONFIG_FILE" 2>/dev/null; then
            record_result "Config Security" "Model allowlist set" "true" 5 "Model allowlist appears configured"
        else
            record_result "Config Security" "Model allowlist set" "false" 5 "No model allowlist configured" "medium"
        fi
    fi
}

check_exec_security() {
    if ! config_exists; then
        record_result "Config Security" "Exec security policy" "true" 5 "No config (defaults apply)"
        return
    fi
    local security
    security=$(json_get "$CONFIG_FILE" '.exec.security' 2>/dev/null)
    if [[ "$security" == "full" ]]; then
        # Check if there's an allowlist
        if json_has "$CONFIG_FILE" '.exec.allowlist' || json_has "$CONFIG_FILE" '.exec.allow'; then
            record_result "Config Security" "Exec security policy" "true" 5 "Exec security 'full' with allowlist"
        else
            record_result "Config Security" "Exec security policy" "false" 5 "Exec security 'full' without allowlist" "high"
        fi
    else
        record_result "Config Security" "Exec security policy" "true" 5 "Exec security is properly configured"
    fi
}

# ── CHECKS: File Exposure (25 pts) ──────────────────────────────────

check_memory_passwords() {
    local mem="$OC_PATH/workspace/MEMORY.md"
    [[ -f "$mem" ]] || mem="$OC_PATH/MEMORY.md"
    if [[ ! -f "$mem" ]]; then
        record_result "File Exposure" "No passwords in MEMORY.md" "true" 10 "No MEMORY.md found"
        return
    fi
    if grep -qiE 'password\s*[:=]\s*\S+|passwd\s*[:=]\s*\S+|secret\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+' "$mem" 2>/dev/null; then
        record_result "File Exposure" "No passwords in MEMORY.md" "false" 10 "Potential passwords/secrets in MEMORY.md" "critical"
    else
        record_result "File Exposure" "No passwords in MEMORY.md" "true" 10 "MEMORY.md clean of plaintext passwords"
    fi
}

check_env_files() {
    local found=false
    while IFS= read -r -d '' env_file; do
        if grep -qE 'sk-[A-Za-z0-9]{20,}|key-[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|password\s*[:=]\s*\S+|secret\s*[:=]\s*\S+' "$env_file" 2>/dev/null; then
            record_result "File Exposure" "No .env secrets" "false" 5 ".env file with secrets found" "high"
            found=true
            break
        fi
    done < <(find "$OC_PATH" -name ".env*" -type f -print0 2>/dev/null)
    if [[ "$found" == "false" ]]; then
        record_result "File Exposure" "No .env secrets" "true" 5 "No .env files with secrets"
    fi
}

check_private_keys() {
    local found=false
    while IFS= read -r -d '' keyfile; do
        if head -c 4096 "$keyfile" 2>/dev/null | grep -q 'BEGIN.*PRIVATE KEY'; then
            record_result "File Exposure" "No private keys" "false" 5 "Private key found in workspace" "critical"
            found=true
            break
        fi
    done < <(find "$OC_PATH" -type f -size -1M -print0 2>/dev/null)
    if [[ "$found" == "false" ]]; then
        record_result "File Exposure" "No private keys" "true" 5 "No private keys in workspace"
    fi
}

check_workspace_permissions() {
    local ws="${WORKSPACE}"
    [[ -d "$ws" ]] || ws="$OC_PATH"
    local perms
    if [[ "$(uname)" == "Darwin" ]]; then
        perms=$(stat -f '%Lp' "$ws" 2>/dev/null || echo "700")
    else
        perms=$(stat -c '%a' "$ws" 2>/dev/null || echo "700")
    fi
    local other_read=$((perms % 10))
    if (( other_read >= 4 )); then
        record_result "File Exposure" "Workspace permissions" "false" 5 "Workspace is world-readable ($perms)" "high"
    else
        record_result "File Exposure" "Workspace permissions" "true" 5 "Workspace permissions are secure ($perms)"
    fi
}

# ── CHECKS: Skill Security (20 pts) ─────────────────────────────────

check_skill_sources() {
    local skills_dir="$OC_PATH/skills"
    if [[ ! -d "$skills_dir" ]]; then
        record_result "Skill Security" "Skills from known sources" "true" 5 "No skills directory"
        return
    fi
    local unknown=()
    while IFS= read -r manifest; do
        local source name
        source=$(json_get "$manifest" '.source' 2>/dev/null)
        name=$(json_get "$manifest" '.name' 2>/dev/null)
        [[ -z "$name" ]] && name=$(basename "$(dirname "$manifest")")
        if [[ -n "$source" ]] && ! echo "$source" | grep -qE 'openclaw|github\.com/openclaw|registry\.openclaw'; then
            unknown+=("$name")
        fi
    done < <(find "$skills_dir" -name "manifest.json" -type f 2>/dev/null)
    if (( ${#unknown[@]} > 0 )); then
        record_result "Skill Security" "Skills from known sources" "false" 5 "Unknown sources: ${unknown[*]:0:3}" "medium"
    else
        record_result "Skill Security" "Skills from known sources" "true" 5 "All skills from known sources"
    fi
}

check_skill_exec_override() {
    local skills_dir="$OC_PATH/skills"
    if [[ ! -d "$skills_dir" ]]; then
        record_result "Skill Security" "No exec override to full" "true" 5 "No skills directory"
        return
    fi
    local bad=""
    while IFS= read -r manifest; do
        if command -v jq &>/dev/null; then
            local sec
            sec=$(jq -r '.exec.security // empty' "$manifest" 2>/dev/null)
            if [[ "$sec" == "full" ]]; then
                bad=$(jq -r '.name // empty' "$manifest" 2>/dev/null)
                break
            fi
        else
            if grep -q '"security".*"full"' "$manifest" 2>/dev/null; then
                bad=$(basename "$(dirname "$manifest")")
                break
            fi
        fi
    done < <(find "$skills_dir" -name "manifest.json" -type f 2>/dev/null)
    if [[ -n "$bad" ]]; then
        record_result "Skill Security" "No exec override to full" "false" 5 "Skill '$bad' overrides exec to 'full'" "high"
    else
        record_result "Skill Security" "No exec override to full" "true" 5 "No skills with exec override to 'full'"
    fi
}

check_skill_permissions() {
    local skills_dir="$OC_PATH/skills"
    if [[ ! -d "$skills_dir" ]]; then
        record_result "Skill Security" "No unjustified elevated perms" "true" 5 "No skills directory"
        return
    fi
    # Simplified: check if any manifest has dangerous permission keywords
    if grep -rlE '"(root|sudo|admin|full_access)"' "$skills_dir" 2>/dev/null | head -1 | grep -q .; then
        record_result "Skill Security" "No unjustified elevated perms" "false" 5 "Skills with elevated permissions found" "high"
    else
        record_result "Skill Security" "No unjustified elevated perms" "true" 5 "No unjustified elevated permissions"
    fi
}

check_skills_dir_writable() {
    local skills_dir="$OC_PATH/skills"
    if [[ ! -d "$skills_dir" ]]; then
        record_result "Skill Security" "Skills dir not world-writable" "true" 5 "No skills directory"
        return
    fi
    local perms
    if [[ "$(uname)" == "Darwin" ]]; then
        perms=$(stat -f '%Lp' "$skills_dir" 2>/dev/null || echo "755")
    else
        perms=$(stat -c '%a' "$skills_dir" 2>/dev/null || echo "755")
    fi
    local other_write=$(( (perms % 10) ))
    if (( other_write >= 2 )); then
        record_result "Skill Security" "Skills dir not world-writable" "false" 5 "Skills directory is world-writable" "high"
    else
        record_result "Skill Security" "Skills dir not world-writable" "true" 5 "Skills directory permissions secure ($perms)"
    fi
}

# ── CHECKS: Network Security (15 pts) ───────────────────────────────

check_gateway_public() {
    if ! config_exists; then
        record_result "Network Security" "Gateway not publicly exposed" "true" 5 "No gateway configuration"
        return
    fi
    local bind
    bind=$(json_get "$CONFIG_FILE" '.gateway.bind' 2>/dev/null)
    local has_auth=false
    json_has "$CONFIG_FILE" '.gateway.auth' && has_auth=true

    if [[ "$bind" != "127.0.0.1" && "$bind" != "localhost" && "$bind" != "::1" && "$bind" != "" && "$has_auth" == "false" ]]; then
        record_result "Network Security" "Gateway not publicly exposed" "false" 5 "Gateway exposed without auth" "critical"
    else
        record_result "Network Security" "Gateway not publicly exposed" "true" 5 "Gateway not publicly exposed without auth"
    fi
}

check_webhooks_https() {
    if ! config_exists; then
        record_result "Network Security" "Webhooks use HTTPS" "true" 5 "No config"
        return
    fi
    if grep -q '"http://' "$CONFIG_FILE" 2>/dev/null; then
        # Check if it's actually a webhook URL
        if command -v jq &>/dev/null; then
            local http_webhooks
            http_webhooks=$(jq -r '.. | .url? // empty' "$CONFIG_FILE" 2>/dev/null | grep -c '^http://' || echo "0")
            if (( http_webhooks > 0 )); then
                record_result "Network Security" "Webhooks use HTTPS" "false" 5 "Webhook configured without HTTPS" "high"
                return
            fi
        fi
    fi
    record_result "Network Security" "Webhooks use HTTPS" "true" 5 "All webhooks use HTTPS (or none configured)"
}

check_browser_cookies() {
    local browser_dir="$OC_PATH/browser"
    if [[ ! -d "$browser_dir" ]]; then
        record_result "Network Security" "Browser cookies secured" "true" 5 "No browser profile directory"
        return
    fi
    local insecure=false
    while IFS= read -r -d '' cf; do
        local perms
        if [[ "$(uname)" == "Darwin" ]]; then
            perms=$(stat -f '%Lp' "$cf" 2>/dev/null || echo "600")
        else
            perms=$(stat -c '%a' "$cf" 2>/dev/null || echo "600")
        fi
        if (( (perms % 10) >= 4 )); then
            insecure=true
            break
        fi
    done < <(find "$browser_dir" -iname "*cookie*" -type f -print0 2>/dev/null)
    if [[ "$insecure" == "true" ]]; then
        record_result "Network Security" "Browser cookies secured" "false" 5 "Browser cookies readable by other users" "high"
    else
        record_result "Network Security" "Browser cookies secured" "true" 5 "Browser cookies are secure"
    fi
}

# ── CHECKS: OpenClaw-Specific (35 pts) ──────────────────────────────

check_config_file_permissions() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        record_result "OpenClaw Security" "Config not world-readable" "true" 5 "No config file"
        return
    fi
    local perms
    if [[ "$(uname)" == "Darwin" ]]; then
        perms=$(stat -f '%Lp' "$CONFIG_FILE" 2>/dev/null || echo "600")
    else
        perms=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || echo "600")
    fi
    if (( (perms % 10) >= 4 )); then
        record_result "OpenClaw Security" "Config not world-readable" "false" 5 "Config file is world-readable ($perms)" "high"
    else
        record_result "OpenClaw Security" "Config not world-readable" "true" 5 "Config file permissions secure ($perms)"
    fi
}

check_gateway_auth_strength() {
    if ! config_exists; then
        record_result "OpenClaw Security" "Auth token strength" "false" 5 "No config file" "medium"
        return
    fi
    local token
    token=$(json_get "$CONFIG_FILE" '.gateway.auth.token' 2>/dev/null)
    [[ -z "$token" ]] && token=$(json_get "$CONFIG_FILE" '.gateway.auth' 2>/dev/null)
    if [[ -z "$token" || "$token" == "null" ]]; then
        record_result "OpenClaw Security" "Auth token strength" "false" 5 "No auth token set" "critical"
    elif (( ${#token} < 16 )); then
        record_result "OpenClaw Security" "Auth token strength" "false" 5 "Auth token too short (${#token} chars, need 16+)" "high"
    else
        record_result "OpenClaw Security" "Auth token strength" "true" 5 "Auth token is strong (${#token} chars)"
    fi
}

check_cron_security() {
    if ! config_exists; then
        record_result "OpenClaw Security" "Cron job security" "true" 5 "No config file"
        return
    fi
    # Check if any cron jobs have elevated: true
    if command -v jq &>/dev/null; then
        local elevated_count
        elevated_count=$(jq '[.cron[]? | select(.elevated == true)] | length' "$CONFIG_FILE" 2>/dev/null || echo "0")
        if (( elevated_count > 0 )); then
            record_result "OpenClaw Security" "Cron job security" "false" 5 "Found $elevated_count cron jobs with elevated privileges" "high"
        else
            record_result "OpenClaw Security" "Cron job security" "true" 5 "No cron jobs with elevated privileges"
        fi
    else
        if grep -q '"elevated".*true' "$CONFIG_FILE" 2>/dev/null; then
            record_result "OpenClaw Security" "Cron job security" "false" 5 "Cron jobs with elevated privileges found" "high"
        else
            record_result "OpenClaw Security" "Cron job security" "true" 5 "No cron jobs with elevated privileges"
        fi
    fi
}

check_memory_exposure() {
    local mem_files=("$OC_PATH/workspace/MEMORY.md" "$OC_PATH/MEMORY.md")
    local mem_dir="$OC_PATH/workspace/memory"
    for mf in "${mem_files[@]}"; do
        if [[ -f "$mf" ]]; then
            local perms
            if [[ "$(uname)" == "Darwin" ]]; then
                perms=$(stat -f '%Lp' "$mf" 2>/dev/null || echo "600")
            else
                perms=$(stat -c '%a' "$mf" 2>/dev/null || echo "600")
            fi
            if (( (perms % 10) >= 4 )); then
                record_result "OpenClaw Security" "Memory files protected" "false" 5 "MEMORY.md is world-readable" "high"
                return
            fi
        fi
    done
    # Check memory directory too
    if [[ -d "$mem_dir" ]]; then
        local perms
        if [[ "$(uname)" == "Darwin" ]]; then
            perms=$(stat -f '%Lp' "$mem_dir" 2>/dev/null || echo "700")
        else
            perms=$(stat -c '%a' "$mem_dir" 2>/dev/null || echo "700")
        fi
        if (( (perms % 10) >= 4 )); then
            record_result "OpenClaw Security" "Memory files protected" "false" 5 "Memory directory is world-readable" "high"
            return
        fi
    fi
    record_result "OpenClaw Security" "Memory files protected" "true" 5 "Memory files are properly protected"
}

check_openclaw_version() {
    if ! command -v openclaw &>/dev/null; then
        record_result "OpenClaw Security" "Version up-to-date" "false" 5 "openclaw command not found" "low"
        return
    fi
    local current
    current=$(openclaw --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    if [[ -z "$current" ]]; then
        record_result "OpenClaw Security" "Version up-to-date" "false" 5 "Could not determine OpenClaw version" "low"
        return
    fi
    # Try to check for updates
    local latest
    latest=$(openclaw update status 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | tail -1 || echo "")
    if [[ -n "$latest" && "$current" != "$latest" ]]; then
        record_result "OpenClaw Security" "Version up-to-date" "false" 5 "Running $current, latest is $latest" "medium"
    else
        record_result "OpenClaw Security" "Version up-to-date" "true" 5 "Running latest version ($current)"
    fi
}

check_workspace_isolation() {
    # Check if workspace is inside a shared/public directory
    local ws="${WORKSPACE}"
    [[ -d "$ws" ]] || ws="$OC_PATH"
    local real_path
    real_path=$(cd "$ws" && pwd -P 2>/dev/null || echo "$ws")

    if echo "$real_path" | grep -qE '^/(tmp|var/tmp|public|shared|Users/Shared)'; then
        record_result "OpenClaw Security" "Workspace isolation" "false" 5 "Workspace in shared/public directory" "high"
    else
        record_result "OpenClaw Security" "Workspace isolation" "true" 5 "Workspace is in a private directory"
    fi
}

# ── Run All Checks ──────────────────────────────────────────────────

run_all_checks() {
    # Config Security (40 pts)
    check_config_exists
    check_no_hardcoded_keys
    check_gateway_auth
    check_gateway_bind
    check_https_configured
    check_model_allowlist
    check_exec_security

    # File Exposure (25 pts)
    check_memory_passwords
    check_env_files
    check_private_keys
    check_workspace_permissions

    # Skill Security (20 pts)
    check_skill_sources
    check_skill_exec_override
    check_skill_permissions
    check_skills_dir_writable

    # Network Security (15 pts)
    check_gateway_public
    check_webhooks_https
    check_browser_cookies

    # OpenClaw-Specific (35 pts)
    check_config_file_permissions
    check_gateway_auth_strength
    check_cron_security
    check_memory_exposure
    check_openclaw_version
    check_workspace_isolation
}

# ── Output ───────────────────────────────────────────────────────────

output_json() {
    local pct=$((TOTAL_SCORE * 100 / MAX_SCORE))
    local grade
    grade=$(get_grade "$pct")

    echo "{"
    echo "  \"version\": \"$VERSION\","
    echo "  \"path\": \"$OC_PATH\","
    echo "  \"score\": $TOTAL_SCORE,"
    echo "  \"maxScore\": $MAX_SCORE,"
    echo "  \"percentage\": $pct,"
    echo "  \"grade\": \"$grade\","
    echo "  \"passed\": $PASS_COUNT,"
    echo "  \"failed\": $FAIL_COUNT,"
    echo "  \"results\": ["

    local first=true
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r category check passed points message severity <<< "$r"
        if [[ "$first" == "true" ]]; then first=false; else echo ","; fi
        printf '    {"category": "%s", "check": "%s", "passed": %s, "points": %s, "message": "%s", "severity": "%s"}' \
            "$category" "$check" "$passed" "$points" "$message" "$severity"
    done
    echo ""
    echo "  ]"
    echo "}"
}

output_text() {
    local pct=$((TOTAL_SCORE * 100 / MAX_SCORE))
    local grade
    grade=$(get_grade "$pct")

    local w=52
    local border
    border=$(printf '═%.0s' $(seq 1 $w))

    echo ""
    echo -e "${BOLD}╔${border}╗${RESET}"
    echo -e "${BOLD}║$(printf '%*s' $(( (w + 24) / 2 )) "CLAWSCAN Security Report")$(printf '%*s' $(( (w - 24) / 2 )) "")║${RESET}"
    echo -e "${BOLD}╠${border}╣${RESET}"

    # Grade line with color
    local grade_color="$GREEN"
    case "$grade" in
        F|D) grade_color="$RED" ;;
        C|C+) grade_color="$YELLOW" ;;
    esac
    echo -e "║  Grade: ${grade_color}${BOLD}${grade}${RESET} (${TOTAL_SCORE}/${MAX_SCORE} pts, ${pct}%)$(printf '%*s' $((w - 28 - ${#grade} - ${#TOTAL_SCORE} - ${#MAX_SCORE} - ${#pct})) "")║"
    echo -e "${BOLD}╠${border}╣${RESET}"

    local current_cat=""
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r category check passed points message severity <<< "$r"

        # Skip passing checks unless verbose
        if [[ "$passed" == "true" && "$VERBOSE" == "false" ]]; then
            if [[ "$category" != "$current_cat" ]]; then
                current_cat="$category"
            fi
            continue
        fi

        if [[ "$category" != "$current_cat" ]]; then
            current_cat="$category"
            local cat_line="  [$current_cat]"
            echo -e "║${BLUE}${BOLD}${cat_line}${RESET}$(printf '%*s' $((w - ${#cat_line})) "")║"
        fi

        local icon msg_line
        if [[ "$passed" == "true" ]]; then
            icon="${GREEN}✅${RESET}"
        else
            icon="${RED}❌${RESET}"
        fi
        # Truncate message if needed
        local display_msg="$message"
        if (( ${#display_msg} > (w - 8) )); then
            display_msg="${display_msg:0:$((w - 9))}…"
        fi
        echo -e "║  ${icon} ${display_msg}$(printf '%*s' $((w - ${#display_msg} - 5)) "")║"
    done

    echo -e "${BOLD}╠${border}╣${RESET}"
    echo -e "║  ${PASS_COUNT} passed, ${FAIL_COUNT} failed$(printf '%*s' $((w - ${#PASS_COUNT} - ${#FAIL_COUNT} - 17)) "")║"
    echo -e "${BOLD}╠${border}╣${RESET}"
    echo -e "║  Pro tier: 15+ advanced checks → clawscan.app$(printf '%*s' $((w - 47)) "")║"
    echo -e "${BOLD}╚${border}╝${RESET}"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────

run_all_checks

if [[ "$JSON_OUTPUT" == "true" ]]; then
    output_json
else
    output_text
fi
