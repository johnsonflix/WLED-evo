#!/usr/bin/env bash
#
# tools/verify-evolights-integration.sh
#
# Asserts that the EvoLights firmware integration is structurally intact.
# Run from the repo root. Exits non-zero on any failure with a clear error.
#
# Designed to catch the failure mode that git merge + the C++ compiler can't:
# upstream silently moves/removes our hooks but the file still parses. We
# preserve every customization with a EVOLIGHTS-ANCHOR comment and grep for it.
#
# This script is invoked by .github/workflows/verify-integration.yml on every
# push to evolights/main and every PR targeting it. It MUST be cheap enough to
# run as a required status check (<5 sec).

# NOT set -e: we want to collect every failure and report them all, then exit
# with the right code at the end. set -u catches typos in our own variables.
set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

PASS=0
FAIL=0
declare -a FAILURES=()

ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); FAILURES+=("$*"); }

section() { echo ""; echo "== $* =="; }

# ---------------------------------------------------------------------
# 1. Required new files exist.
# ---------------------------------------------------------------------
section "Required EvoLights files present"
for f in \
  wled00/wled_cloud_auth.h \
  wled00/wled_cloud_auth.cpp \
  usermods/cloud_relay/cloud_relay.cpp \
  usermods/cloud_relay/library.json \
; do
  if [[ -f "$f" ]]; then ok "$f"
  else fail "missing: $f"
  fi
done

# ---------------------------------------------------------------------
# 2. Anchor comments present in the upstream files we patched. If a future
#    upstream merge silently wipes our edits, the anchors disappear with them.
# ---------------------------------------------------------------------
section "Anchors in patched upstream files"

# Map anchor name -> file it must appear in.
declare -A ANCHORS=(
  ["include-auth-header:wled00/wled.cpp"]=1
  ["auth-init-call:wled00/wled.cpp"]=1
  ["include-auth-header:wled00/cfg.cpp"]=1
  ["auth-read-wsec:wled00/cfg.cpp"]=1
  ["auth-write-wsec:wled00/cfg.cpp"]=1
  ["env-evolights:platformio.ini"]=1
  # Build glue that lets usermods #include framework headers like
  # <WiFiClientSecure.h>. Without these, cloud_relay's TLS code goes back
  # to "WiFiClientSecure.h: No such file or directory" at compile time.
  # Two layers (belt + suspenders): the env-scope script injects -I flags into
  # the env's CCFLAGS so every compile in the env sees them; the per-lib hook
  # in load_usermods.py is the fallback that prepends to each usermod's CPPPATH.
  ["usermod-framework-includes:pio-scripts/load_usermods.py"]=1
  ["usermod-framework-includes-apply:pio-scripts/load_usermods.py"]=1
  ["expose-framework-libs:pio-scripts/expose_framework_libs.py"]=1
  ["evolights-extra-scripts:platformio.ini"]=1
  # TLS for the cloud relay MQTT transport. If any of these go missing, the
  # device has either dropped TLS entirely, stopped pinning the CA, or stopped
  # failing closed when no CA cert is provisioned.
  ["cloud-relay-tls-client:usermods/cloud_relay/cloud_relay.cpp"]=1
  ["cloud-relay-tls-fail-closed:usermods/cloud_relay/cloud_relay.cpp"]=1
  ["cloud-relay-tls-pin-ca:usermods/cloud_relay/cloud_relay.cpp"]=1
)

for key in "${!ANCHORS[@]}"; do
  anchor="${key%%:*}"
  file="${key##*:}"
  if [[ ! -f "$file" ]]; then
    fail "anchor host file missing: $file (expected EVOLIGHTS-ANCHOR: $anchor)"
    continue
  fi
  start_count=$(grep -c "EVOLIGHTS-ANCHOR: ${anchor}\$" "$file" || true)
  end_count=$(grep -c "EVOLIGHTS-ANCHOR: ${anchor}-end\$" "$file" || true)
  if [[ "$start_count" -ge 1 && "$end_count" -ge 1 ]]; then
    ok "$file: anchor '$anchor' (open+close found)"
  else
    fail "$file: anchor '$anchor' missing or unbalanced (start=$start_count end=$end_count)"
  fi
done

# ---------------------------------------------------------------------
# 3. Symbol-level invariants — what each anchor MUST contain. This is the
#    layer that catches "anchor preserved but our actual call was removed".
# ---------------------------------------------------------------------
section "Hook calls present"

require_in_file() {
  local file="$1" pattern="$2" label="$3"
  if grep -qE "$pattern" "$file"; then ok "$label"
  else fail "$label  (pattern: $pattern in $file)"
  fi
}

# Anchor patterns to lines that begin with optional whitespace and the call
# itself — comments like "// EvoAuth::init(server) does X" are deliberately
# NOT matched, because what we care about is the live call, not a mention.
require_in_file wled00/wled.cpp '^[[:space:]]*#include "wled_cloud_auth\.h"' "wled.cpp includes wled_cloud_auth.h"
require_in_file wled00/wled.cpp '^[[:space:]]*EvoAuth::init\(server\);'      "wled.cpp calls EvoAuth::init(server)"

require_in_file wled00/cfg.cpp '^[[:space:]]*#include "wled_cloud_auth\.h"' "cfg.cpp includes wled_cloud_auth.h"
require_in_file wled00/cfg.cpp '^[[:space:]]*EvoAuth::readFromWsec\(root\);' "cfg.cpp calls EvoAuth::readFromWsec(root)"
require_in_file wled00/cfg.cpp '^[[:space:]]*EvoAuth::writeToWsec\(root\);' "cfg.cpp calls EvoAuth::writeToWsec(root)"

require_in_file usermods/cloud_relay/cloud_relay.cpp 'REGISTER_USERMOD' \
  "cloud_relay registers itself via REGISTER_USERMOD"

# TLS invariants — these encode the security promise: real WiFiClientSecure,
# real CA pinning, real fail-closed when no CA is on file. None of these may
# silently regress to plaintext or setInsecure().
require_in_file usermods/cloud_relay/cloud_relay.cpp '#include <WiFiClientSecure\.h>' \
  "cloud_relay includes <WiFiClientSecure.h>"
require_in_file usermods/cloud_relay/cloud_relay.cpp 'WiFiClientSecure[[:space:]]+g_tls' \
  "cloud_relay declares a WiFiClientSecure transport (g_tls)"
require_in_file usermods/cloud_relay/cloud_relay.cpp 'g_tls\.setCACert\(' \
  "cloud_relay pins the CA cert via setCACert()"
require_in_file usermods/cloud_relay/cloud_relay.cpp 'new PubSubClient\(g_tls\)' \
  "cloud_relay's PubSubClient sits on top of WiFiClientSecure"
# Hard guard: setInsecure() must NOT appear as a live call. If anyone is
# tempted to silence a TLS error by switching to setInsecure(), this catches
# the regression at verifier time before it ships. We match a real call (a
# leading identifier-or-`.` followed by setInsecure) rather than the bare
# token, so doc comments that mention the function name don't trip the guard.
if grep -qE '(^|[^/A-Za-z_])(\.|->)setInsecure[[:space:]]*\(' usermods/cloud_relay/cloud_relay.cpp; then
  fail "cloud_relay.cpp uses setInsecure() — TLS validation is disabled, refusing to ship"
else
  ok "cloud_relay.cpp does not call setInsecure() (TLS validation is enforced)"
fi
# And we never want plain WiFiClient as the MQTT transport again.
if grep -qE 'new PubSubClient\(g_tcp\)|PubSubClient[[:space:]]*\([[:space:]]*WiFiClient[^S]' usermods/cloud_relay/cloud_relay.cpp; then
  fail "cloud_relay.cpp wires PubSubClient over plain WiFiClient — TLS bypassed"
else
  ok "cloud_relay.cpp does not wire PubSubClient over plain WiFiClient"
fi

# EvoLights envs in platformio.ini — what firmware-build.yml builds.
require_in_file platformio.ini '^\[env:esp32dev_evolights\]'             "platformio.ini: env esp32dev_evolights defined"
require_in_file platformio.ini '^\[env:esp32_eth_evolights\]'            "platformio.ini: env esp32_eth_evolights defined"
require_in_file platformio.ini '^\[env:esp32s3dev_8MB_qspi_evolights\]'  "platformio.ini: env esp32s3dev_8MB_qspi_evolights defined"

# ---------------------------------------------------------------------
# 4. Ordering invariant — the AuthGate MUST be registered before usermod
#    setup runs (otherwise usermod-registered HTTP handlers escape the gate)
#    AND before initServer (otherwise WLED's own routes escape it).
# ---------------------------------------------------------------------
section "Setup ordering in wled.cpp"

# Get line number of the first ACTUAL call site (leading whitespace, trailing
# semicolon) — not a mention inside a comment. The anchor comments above
# reference these symbols by name and would confuse a naive grep.
callsite() { grep -nE "^[[:space:]]*$1;" wled00/wled.cpp | head -1 | cut -d: -f1; }

L_INIT=$(callsite 'EvoAuth::init\(server\)')
L_USERMOD=$(callsite 'UsermodManager::setup\(\)')
L_INITSERVER=$(callsite 'initServer\(\)')

missing=""
[[ -z "$L_INIT"       ]] && missing="$missing EvoAuth::init"
[[ -z "$L_USERMOD"    ]] && missing="$missing UsermodManager::setup"
[[ -z "$L_INITSERVER" ]] && missing="$missing initServer"

if [[ -n "$missing" ]]; then
  fail "could not locate call site(s):${missing} — file may have been refactored or our hook removed"
else
  if [[ "$L_INIT" -lt "$L_USERMOD" ]]; then
    ok "EvoAuth::init (line $L_INIT) before UsermodManager::setup (line $L_USERMOD)"
  else
    fail "EvoAuth::init (line $L_INIT) is NOT before UsermodManager::setup (line $L_USERMOD) — usermod routes will escape the auth gate"
  fi
  if [[ "$L_INIT" -lt "$L_INITSERVER" ]]; then
    ok "EvoAuth::init (line $L_INIT) before initServer (line $L_INITSERVER)"
  else
    fail "EvoAuth::init (line $L_INIT) is NOT before initServer (line $L_INITSERVER) — WLED routes will escape the auth gate"
  fi
fi

# ---------------------------------------------------------------------
# 5. Data integrity — auth header still declares the symbols cfg.cpp uses.
# ---------------------------------------------------------------------
section "Auth API surface"

require_in_file wled00/wled_cloud_auth.h 'void init\(AsyncWebServer'        "EvoAuth::init declared"
require_in_file wled00/wled_cloud_auth.h 'bool readFromWsec\(.*JsonObject'  "EvoAuth::readFromWsec declared"
require_in_file wled00/wled_cloud_auth.h 'void writeToWsec\(.*JsonObject'      "EvoAuth::writeToWsec declared"
require_in_file wled00/wled_cloud_auth.h 'cloudTrustedToken\(\)'              "EvoAuth::cloudTrustedToken declared (cloud_relay depends on it)"

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
echo ""
echo "================================================================"
echo "EvoLights integration verification: $PASS passed, $FAIL failed"
echo "================================================================"

if (( FAIL > 0 )); then
  echo ""
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  echo ""
  echo "An upstream sync likely damaged the EvoLights integration."
  echo "Inspect the offending file(s), restore the hook, and re-run."
  exit 1
fi
echo ""
echo "All EvoLights integration invariants hold."
