#!/usr/bin/env bash
# ClawScan Report Formatter — reads JSON from stdin, outputs formatted report
set -euo pipefail

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
    BLUE='\033[0;34m' BOLD='\033[1m' RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' RESET=''
fi

# Read JSON from stdin
INPUT=$(cat)

if ! command -v jq &>/dev/null; then
    echo "Error: jq required for report formatting from JSON"
    echo "Install: brew install jq (macOS) or apt install jq (Linux)"
    exit 1
fi

GRADE=$(echo "$INPUT" | jq -r '.grade')
SCORE=$(echo "$INPUT" | jq -r '.score')
MAX=$(echo "$INPUT" | jq -r '.maxScore')
PCT=$(echo "$INPUT" | jq -r '.percentage')
PASSED=$(echo "$INPUT" | jq -r '.passed')
FAILED=$(echo "$INPUT" | jq -r '.failed')
PATH_SCANNED=$(echo "$INPUT" | jq -r '.path')

w=52
border=$(printf '═%.0s' $(seq 1 $w))

echo ""
echo -e "${BOLD}╔${border}╗${RESET}"
echo -e "${BOLD}║$(printf '%*s' $(( (w + 24) / 2 )) "CLAWSCAN Security Report")$(printf '%*s' $(( (w - 24) / 2 )) "")║${RESET}"
echo -e "${BOLD}╠${border}╣${RESET}"

grade_color="$GREEN"
case "$GRADE" in F|D) grade_color="$RED" ;; C|C+) grade_color="$YELLOW" ;; esac

echo -e "║  Path: ${PATH_SCANNED}$(printf '%*s' $((w - 8 - ${#PATH_SCANNED})) "")║"
echo -e "║  Grade: ${grade_color}${BOLD}${GRADE}${RESET} (${SCORE}/${MAX} pts, ${PCT}%)$(printf '%*s' $((w - 28 - ${#GRADE} - ${#SCORE} - ${#MAX} - ${#PCT})) "")║"
echo -e "${BOLD}╠${border}╣${RESET}"

# Group results by category
CATEGORIES=$(echo "$INPUT" | jq -r '[.results[].category] | unique | .[]')

while IFS= read -r cat; do
    echo -e "║${BLUE}${BOLD}  [$cat]${RESET}$(printf '%*s' $((w - ${#cat} - 4)) "")║"

    echo "$INPUT" | jq -c ".results[] | select(.category == \"$cat\")" | while IFS= read -r result; do
        local_passed=$(echo "$result" | jq -r '.passed')
        msg=$(echo "$result" | jq -r '.message')
        severity=$(echo "$result" | jq -r '.severity')

        if [[ "$local_passed" == "true" ]]; then
            icon="${GREEN}✅${RESET}"
        else
            icon="${RED}❌${RESET}"
            [[ "$severity" == "critical" ]] && msg="[CRITICAL] $msg"
        fi

        if (( ${#msg} > (w - 8) )); then
            msg="${msg:0:$((w - 9))}…"
        fi
        echo -e "║  ${icon} ${msg}$(printf '%*s' $((w - ${#msg} - 5)) "")║"
    done
done <<< "$CATEGORIES"

echo -e "${BOLD}╠${border}╣${RESET}"
echo -e "║  ${GREEN}${PASSED} passed${RESET}, ${RED}${FAILED} failed${RESET}$(printf '%*s' $((w - ${#PASSED} - ${#FAILED} - 17)) "")║"
echo -e "${BOLD}╚${border}╝${RESET}"
echo ""
