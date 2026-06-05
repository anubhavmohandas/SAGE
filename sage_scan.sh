#!/bin/bash
# sage_scan.sh — Interactive SAGE setup + scan launcher
#
# What it does:
#   1. Asks which repo to scan (or takes it as argument)
#   2. Detects GitHub remote from the repo's git config
#   3. If remote doesn't match GITHUB_REPO in .env — asks and updates .env
#   4. Clears the remembered GitHub repo choice for this repo (fresh start)
#   5. Launches the full SAGE pipeline
#
# Usage:
#   bash sage_scan.sh                          # interactive — asks for repo path
#   bash sage_scan.sh /path/to/repo            # skip the path question
#   bash sage_scan.sh /path/to/repo --days 7   # with extra flags passed to main.py

set -e
SAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SAGE_DIR/.env"

# ── Colors ────────────────────────────────────────────────────────────────────
BOLD="\033[1m"
CYAN="\033[96m"
GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
DIM="\033[2m"
RESET="\033[0m"

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║   SAGE — Security Analysis & Graph Engine    ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════╝${RESET}"
# Gradient "Made by Anubhav" using ANSI 256-color escape codes
# Colors: purple(93) → blue(63) → cyan(51) → light-cyan(159)
printf "        \033[38;5;93m⚡\033[0m \033[38;5;93mM\033[38;5;99ma\033[38;5;63md\033[38;5;27me\033[38;5;33m \033[38;5;39mb\033[38;5;45my\033[38;5;51m \033[38;5;87mA\033[38;5;123mn\033[38;5;159mu\033[38;5;195mb\033[38;5;231mh\033[38;5;195ma\033[38;5;159mv\033[0m\n"
echo ""

# ── Step 1: Get repo path ─────────────────────────────────────────────────────
REPO_PATH="${1:-}"
EXTRA_ARGS="${@:2}"  # everything after the first arg passed to main.py

if [ -z "$REPO_PATH" ]; then
    echo -e "${BOLD}Which repo do you want to scan?${RESET}"
    echo -e "${DIM}Enter full path (e.g. /Users/you/projects/MyApp)${RESET}"
    read -r -p "  Repo path: " REPO_PATH
    REPO_PATH="${REPO_PATH/#\~/$HOME}"  # expand ~
fi

if [ ! -d "$REPO_PATH" ]; then
    echo -e "${RED}[sage] Directory not found: $REPO_PATH${RESET}"
    exit 1
fi

REPO_NAME=$(basename "$REPO_PATH")
echo ""
echo -e "${BOLD}Repo:${RESET} $REPO_PATH ${DIM}($REPO_NAME)${RESET}"

# ── Step 2: Detect GitHub remote ─────────────────────────────────────────────
DETECTED_GITHUB=""
if [ -d "$REPO_PATH/.git" ]; then
    RAW_REMOTE=$(git -C "$REPO_PATH" remote get-url origin 2>/dev/null || echo "")
    if [ -n "$RAW_REMOTE" ]; then
        # Extract owner/repo from HTTPS or SSH
        DETECTED_GITHUB=$(echo "$RAW_REMOTE" | \
            sed -E 's|.*github\.com[/:]([^/]+/[^/]+?)(\.git)?$|\1|' 2>/dev/null || echo "")
    fi
fi

# ── Step 3: Read current .env GITHUB_REPO ────────────────────────────────────
CURRENT_ENV_REPO=""
if [ -f "$ENV_FILE" ]; then
    CURRENT_ENV_REPO=$(grep "^GITHUB_REPO=" "$ENV_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d "'" | tr -d ' ')
fi

echo ""
if [ -n "$DETECTED_GITHUB" ]; then
    echo -e "  GitHub remote detected: ${GREEN}${DETECTED_GITHUB}${RESET}"
else
    echo -e "  ${YELLOW}No GitHub remote found in repo${RESET}"
fi
echo -e "  GITHUB_REPO in .env:    ${DIM}${CURRENT_ENV_REPO:-not set}${RESET}"

# ── Step 4: Handle mismatch / missing ────────────────────────────────────────
TARGET_REPO=""

if [ -n "$DETECTED_GITHUB" ] && [ "$DETECTED_GITHUB" = "$CURRENT_ENV_REPO" ]; then
    # Perfect match — no action needed
    TARGET_REPO="$DETECTED_GITHUB"
    echo -e "  ${GREEN}✓ GitHub repo matches .env — no changes needed${RESET}"

elif [ -n "$DETECTED_GITHUB" ] && [ -n "$CURRENT_ENV_REPO" ] && [ "$DETECTED_GITHUB" != "$CURRENT_ENV_REPO" ]; then
    # Mismatch — ask
    echo ""
    echo -e "${YELLOW}  GITHUB_REPO in .env doesn't match this repo's remote.${RESET}"
    echo -e "  [1] Update .env to use ${BOLD}$DETECTED_GITHUB${RESET} (detected)"
    echo -e "  [2] Keep .env as ${DIM}$CURRENT_ENV_REPO${RESET}"
    echo -e "  [3] Enter a different owner/repo manually"
    read -r -p "  Choice (1/2/3): " choice
    case "$choice" in
        1) TARGET_REPO="$DETECTED_GITHUB" ;;
        2) TARGET_REPO="$CURRENT_ENV_REPO" ;;
        3)
            read -r -p "  Enter owner/repo (e.g. anubhavmohandas/MyApp): " TARGET_REPO
            ;;
        *) TARGET_REPO="$DETECTED_GITHUB" ;;
    esac

elif [ -z "$CURRENT_ENV_REPO" ]; then
    # .env has no GITHUB_REPO set
    if [ -n "$DETECTED_GITHUB" ]; then
        echo ""
        echo -e "  GITHUB_REPO not set in .env."
        echo -e "  [1] Set to ${BOLD}$DETECTED_GITHUB${RESET} (detected from remote)"
        echo -e "  [2] Enter manually"
        echo -e "  [3] Skip (no PR creation)"
        read -r -p "  Choice (1/2/3): " choice
        case "$choice" in
            1) TARGET_REPO="$DETECTED_GITHUB" ;;
            2) read -r -p "  Enter owner/repo: " TARGET_REPO ;;
            *) TARGET_REPO="" ;;
        esac
    else
        echo ""
        echo -e "  No GitHub remote found and GITHUB_REPO not set in .env."
        echo -e "  [1] Enter GitHub repo (owner/repo) for PR creation"
        echo -e "  [2] Skip GitHub PR"
        read -r -p "  Choice (1/2): " choice
        if [ "$choice" = "1" ]; then
            read -r -p "  Enter owner/repo: " TARGET_REPO
        fi
    fi

else
    TARGET_REPO="$CURRENT_ENV_REPO"
fi

# ── Step 5: Update .env if needed ────────────────────────────────────────────
if [ -n "$TARGET_REPO" ] && [ "$TARGET_REPO" != "$CURRENT_ENV_REPO" ]; then
    if [ -f "$ENV_FILE" ]; then
        if grep -q "^GITHUB_REPO=" "$ENV_FILE"; then
            # Replace existing line
            if [[ "$OSTYPE" == "darwin"* ]]; then
                sed -i '' "s|^GITHUB_REPO=.*|GITHUB_REPO=$TARGET_REPO|" "$ENV_FILE"
            else
                sed -i "s|^GITHUB_REPO=.*|GITHUB_REPO=$TARGET_REPO|" "$ENV_FILE"
            fi
        else
            echo "GITHUB_REPO=$TARGET_REPO" >> "$ENV_FILE"
        fi
    else
        echo "GITHUB_REPO=$TARGET_REPO" > "$ENV_FILE"
    fi
    echo -e "  ${GREEN}✓ .env updated: GITHUB_REPO=$TARGET_REPO${RESET}"
fi

# ── Step 6: Clear remembered choice so config.py doesn't use stale cache ─────
CACHE_FILE="$SAGE_DIR/data/$REPO_NAME/.github_repo"
if [ -f "$CACHE_FILE" ]; then
    rm -f "$CACHE_FILE"
fi

# ── Step 7: Ask for scan depth ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Scan window${RESET} ${DIM}(days of CVE history to fetch)${RESET}"
echo -e "  [1] 1 day   — today's CVEs only (fast)"
echo -e "  [2] 7 days  — last week (recommended)"
echo -e "  [3] 30 days — last month (thorough)"
echo -e "  [4] Custom"
read -r -p "  Choice (1/2/3/4) [default: 2]: " days_choice
case "${days_choice:-2}" in
    1) DAYS=1 ;;
    2) DAYS=7 ;;
    3) DAYS=30 ;;
    4) read -r -p "  Enter number of days: " DAYS ;;
    *) DAYS=7 ;;
esac

# ── Step 8: Launch ────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}Scanning:${RESET}   $REPO_PATH"
echo -e "  ${BOLD}GitHub PR:${RESET}  ${TARGET_REPO:-disabled}"
echo -e "  ${BOLD}Days:${RESET}       $DAYS"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

cd "$SAGE_DIR"
source venv/bin/activate 2>/dev/null || true
python3 main.py --repo "$REPO_PATH" --days "$DAYS" $EXTRA_ARGS
