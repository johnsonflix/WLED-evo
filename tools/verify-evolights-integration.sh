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
  usermods/cloud_relay/ota_verifier.h \
  usermods/cloud_relay/ota_verifier.cpp \
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
  # Critical-finding fixes (PR fix/firmware-criticals): each invariant below
  # corresponds to a specific security regression we don't want silently
  # reintroduced by a future merge.
  ["cloud-token-loopback-only:wled00/wled_cloud_auth.cpp"]=1
  ["cloud-pairing-session-only:wled00/wled_cloud_auth.cpp"]=1
  ["ap-setup-allowlist:wled00/wled_cloud_auth.cpp"]=1
  ["auth-setup-mutex:wled00/wled_cloud_auth.cpp"]=1
  ["auth-setup-presence:wled00/wled_cloud_auth.cpp"]=1
  ["session-lru-eviction:wled00/wled_cloud_auth.cpp"]=1
  ["cookie-parse-anchored:wled00/wled_cloud_auth.cpp"]=1
  ["login-timing-oracle-verify:wled00/wled_cloud_auth.cpp"]=1
  ["pbkdf2-iters:wled00/wled_cloud_auth.h"]=1
  # OTA verifier (PR feat/firmware-signed-ota): pubkey present + downgrade
  # protection in code + trust-model comment block. Without these, signed-OTA
  # silently regresses to "any signed manifest gets flashed".
  ["ota-pubkey:usermods/cloud_relay/ota_verifier.cpp"]=1
  ["ota-downgrade-protection:usermods/cloud_relay/ota_verifier.cpp"]=1
  ["ota-trust-model:usermods/cloud_relay/ota_verifier.cpp"]=1
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

# EvoLights envs in platformio.ini — what firmware-build.yml builds.
require_in_file platformio.ini '^\[env:esp32dev_evolights\]'             "platformio.ini: env esp32dev_evolights defined"
require_in_file platformio.ini '^\[env:esp32_eth_evolights\]'            "platformio.ini: env esp32_eth_evolights defined"
require_in_file platformio.ini '^\[env:esp32s3dev_8MB_qspi_evolights\]'  "platformio.ini: env esp32s3dev_8MB_qspi_evolights defined"

# OTA verifier wiring — cloud_relay must dispatch /ota MQTT messages to the verifier.
require_in_file usermods/cloud_relay/cloud_relay.cpp '#include "ota_verifier\.h"' \
  "cloud_relay includes ota_verifier.h"
require_in_file usermods/cloud_relay/cloud_relay.cpp 'EvoLights::OTA::processManifest' \
  "cloud_relay dispatches /ota MQTT messages to OTA::processManifest"

# OTA pubkey is non-empty (catch the case where someone removed the key bytes
# but left the constant declaration).
if grep -qE '^[[:space:]]*"[A-Za-z0-9+/=]{40,}"' usermods/cloud_relay/ota_verifier.cpp; then
  ok "ota_verifier.cpp: OTA_PUBKEY_B64 has a non-empty base64 value"
else
  fail "ota_verifier.cpp: OTA_PUBKEY_B64 is empty or malformed"
fi

# OTA downgrade protection: code MUST refuse manifests where manifestVer <= currentVer.
# Without this, a signed older manifest can be replayed to roll back security fixes.
require_in_file usermods/cloud_relay/ota_verifier.cpp 'manifestVer <= currentVer' \
  "ota_verifier.cpp enforces downgrade protection (manifestVer > currentVer)"

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
# 6. Security invariants (positive checks for the critical-finding fixes).
# ---------------------------------------------------------------------
section "Security invariants"

# PBKDF2 must be at least 50000 iters.
if grep -qE 'PBKDF2_ITERS = (5[0-9]{4}|[6-9][0-9]{4}|[1-9][0-9]{5,})' wled00/wled_cloud_auth.h; then
  ok "PBKDF2_ITERS >= 50000 in wled_cloud_auth.h"
else
  fail "PBKDF2_ITERS appears below 50000 — login is vulnerable to brute force"
fi

# Cloud-trusted token must be loopback-gated.
require_in_file wled00/wled_cloud_auth.cpp 'isLoopbackPeer' \
  "isLoopbackPeer helper is referenced (cloud token loopback-only)"

# /cloud/pair and /cloud/unpair must be mentioned by the pairing-session-only
# code path so a future refactor can't silently drop the special case.
require_in_file wled00/wled_cloud_auth.cpp '/cloud/pair' \
  "/cloud/pair is referenced in isAuthorized (cloud-pairing-session-only)"
require_in_file wled00/wled_cloud_auth.cpp '/cloud/unpair' \
  "/cloud/unpair is referenced in isAuthorized (cloud-pairing-session-only)"

# Setup mutex flag must exist.
require_in_file wled00/wled_cloud_auth.cpp 'g_setupInProgress' \
  "/auth/setup mutex flag g_setupInProgress present"

# Cookie parser must contain anchored marker logic (look for the comment
# describing the start-of-string OR '; ' rule, AND the actual char checks).
require_in_file wled00/wled_cloud_auth.cpp "atStart" \
  "Cookie parser contains anchored start-of-string check"
require_in_file wled00/wled_cloud_auth.cpp "afterDelim" \
  "Cookie parser contains anchored after-delimiter check"

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
