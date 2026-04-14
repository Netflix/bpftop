#!/usr/bin/env bash
# Hardened wrapper for issue triage. Pins all operations to the
# triggering issue and validates labels against an allowlist.
# Prevents prompt-injection exfil by constraining what Claude can do.
set -euo pipefail

VALID_LABELS=("bug" "enhancement" "question" "bpf" "tui" "build" "docs" "duplicate")

[[ -z "${ISSUE_NUMBER:-}" ]] && { echo "ERROR: ISSUE_NUMBER not set"; exit 1; }
[[ "$ISSUE_NUMBER" =~ ^[0-9]+$ ]] || { echo "ERROR: ISSUE_NUMBER must be numeric"; exit 1; }

case "${1:-}" in
  get)
    # Read the triggering issue only
    gh issue view "$ISSUE_NUMBER" --json number,title,body,labels,state
    ;;
  add-label)
    label="${2:-}"
    valid=false
    for l in "${VALID_LABELS[@]}"; do
      [[ "$l" == "$label" ]] && valid=true
    done
    if ! $valid; then
      echo "ERROR: invalid label '$label'. Allowed: ${VALID_LABELS[*]}"
      exit 1
    fi
    gh issue edit "$ISSUE_NUMBER" --add-label "$label"
    ;;
  comment)
    # Only comments on the triggering issue. Length-limited.
    message="${2:-}"
    [[ -z "$message" ]] && { echo "ERROR: comment message required"; exit 1; }
    if (( ${#message} > 2000 )); then
      echo "ERROR: comment too long (max 2000 chars)"
      exit 1
    fi
    gh issue comment "$ISSUE_NUMBER" --body "$message"
    ;;
  search)
    # Read-only search for duplicates
    query="${2:-}"
    [[ -z "$query" ]] && { echo "ERROR: search query required"; exit 1; }
    gh issue list --search "$query" --limit 10 --json number,title,state,labels
    ;;
  *)
    echo "Usage: triage-issue.sh {get|add-label|comment|search} [args]"
    echo "  get                   — read the triggering issue"
    echo "  add-label <label>     — add a label (${VALID_LABELS[*]})"
    echo "  comment <message>     — comment on the triggering issue (max 2000 chars)"
    echo "  search <query>        — search for similar issues"
    exit 1
    ;;
esac
