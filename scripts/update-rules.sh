#!/usr/bin/env bash
# ClawScan Rule Updater — checks for new rule versions
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="$SCRIPT_DIR/../assets/baseline-rules.json"
UPDATE_URL="https://raw.githubusercontent.com/osmankidwai-bot/clawscan/main/clawscan/assets/baseline-rules.json"
STATE_DIR="${HOME}/.clawscan"
UPDATE_LOG="$STATE_DIR/update-log.json"

mkdir -p "$STATE_DIR"

# Get current version
if command -v jq &>/dev/null; then
    CURRENT=$(jq -r '.version' "$RULES_FILE" 2>/dev/null || echo "0.0.0")
else
    CURRENT=$(grep -oP '"version"\s*:\s*"\K[^"]+' "$RULES_FILE" 2>/dev/null || echo "0.0.0")
fi

echo "Current rules version: $CURRENT"

# Fetch latest
TEMP=$(mktemp)
if curl -sfL "$UPDATE_URL" -o "$TEMP" 2>/dev/null; then
    if command -v jq &>/dev/null; then
        LATEST=$(jq -r '.version' "$TEMP" 2>/dev/null || echo "")
    else
        LATEST=$(grep -oP '"version"\s*:\s*"\K[^"]+' "$TEMP" 2>/dev/null || echo "")
    fi

    if [[ -z "$LATEST" ]]; then
        echo "Error: Could not parse remote rules version"
        rm -f "$TEMP"
        exit 1
    fi

    if [[ "$CURRENT" == "$LATEST" ]]; then
        echo "Already up to date ($CURRENT)"
    else
        echo "Update available: $CURRENT → $LATEST"
        # Backup current rules
        cp "$RULES_FILE" "$RULES_FILE.bak"
        # Apply update
        mv "$TEMP" "$RULES_FILE"
        echo "Updated to $LATEST (backup at baseline-rules.json.bak)"

        # Log update
        echo "{\"from\": \"$CURRENT\", \"to\": \"$LATEST\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$UPDATE_LOG"
    fi
else
    echo "Could not reach update server. Using local rules ($CURRENT)."
fi

rm -f "$TEMP" 2>/dev/null
