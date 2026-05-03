#include "wled.h"        // brings in ArduinoJson (vendored), ESPAsyncWebServer, IPAddress
#include "wled_cloud_auth.h"

#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

#if defined(ESP32)
  #include <esp_random.h>
#endif

namespace EvoAuth {

namespace {

  // ---- Persisted credentials (mirrored from wsec.json) ----
  char g_username[USERNAME_MAX + 1] = {0};
  char g_hashBlob[HASH_BLOB_MAX + 1] = {0};        // "v1$<iters>$<salt_b64>$<hash_b64>"
  bool g_localEnabled = true;                       // master switch (settings UI later)

  // ---- In-RAM cloud bypass token ----
  bool g_cloudBypassEnabled = false;
  char g_cloudToken[TOKEN_LEN + 1] = {0};

  // ---- In-RAM session table ----
  struct Session {
    char     token[TOKEN_LEN + 1];
    uint32_t expiresAt;                              // millis()
    uint32_t lastUsedAt;                             // millis() of last hit (for LRU eviction)
  };
  Session g_sessions[MAX_SESSIONS] = {};

  // ---- /auth/setup race protection ----
  // EVOLIGHTS-ANCHOR: auth-setup-mutex
  // Prevents two near-simultaneous /auth/setup POSTs from both passing the
  // isConfigured() check before either writes credentials. Only the first one
  // to flip this flag is allowed through; the second sees 409. The flag is
  // cleared on every code path including errors via the SetupGuard RAII helper.
  volatile bool g_setupInProgress = false;
  // EVOLIGHTS-ANCHOR: auth-setup-mutex-end

  struct SetupGuard {
    bool acquired;
    SetupGuard() : acquired(false) {}
    ~SetupGuard() { if (acquired) g_setupInProgress = false; }
  };

  // ---- Dummy hash used to keep verifyPassword() runtime constant ----
  // EVOLIGHTS-ANCHOR: login-timing-oracle
  // Without this, an attacker can distinguish "user exists, wrong password"
  // (~PBKDF2 cost) from "user doesn't exist" (instant). We always run PBKDF2
  // against this fixed salt+hash so the timing is the same either way.
  uint8_t g_dummySalt[16] = {0};
  uint8_t g_dummyHash[32] = {0};
  bool    g_dummyReady = false;
  // EVOLIGHTS-ANCHOR: login-timing-oracle-end

  // ---- Allow-list of paths that bypass auth entirely ----
  // Static assets the login page itself needs, plus auth endpoints and the
  // captive-portal probe URLs Android/iOS hit during AP setup.
  bool isPublicPath(const String &url) {
    if (url.startsWith(F("/auth/"))) return true;
    if (url == F("/favicon.ico")) return true;
    if (url == F("/style.css")) return true;
    if (url == F("/skin.css")) return true;
    if (url == F("/common.js")) return true;
    if (url == F("/version")) return true;          // discovery probe
    // Captive portal probes — let WLED's existing captive handler answer.
    if (url == F("/generate_204")) return true;
    if (url == F("/gen_204")) return true;
    if (url == F("/hotspot-detect.html")) return true;
    if (url == F("/ncsi.txt")) return true;
    return false;
  }

  // EVOLIGHTS-ANCHOR: ap-setup-allowlist
  // While the device is in initial-AP-setup mode (apActive && !WiFi configured),
  // ONLY the routes needed to complete WiFi setup bypass auth. Previously the
  // entire UI (incl. /edit, /update, /json/cfg, /settings/sec) was wide open
  // during this window, which let any AP visitor own the device before the
  // owner had a chance to create an admin account.
  bool isWifiSetupAllowed(const String &u) {
    if (u == F("/")) return true;
    if (u.startsWith(F("/welcome"))) return true;
    if (u.startsWith(F("/settings/wifi"))) return true;     // also matches .js
    if (u == F("/settings")) return true;                   // settings menu
    if (u == F("/settings.js")) return true;
    if (u == F("/settings/wifi.js")) return true;
    if (u.endsWith(F(".js"))) return true;                  // helper bundles
    if (u.endsWith(F(".css"))) return true;
    if (u == F("/favicon.ico")) return true;
    return false;
  }
  // EVOLIGHTS-ANCHOR: ap-setup-allowlist-end

  // -------------------------------------------------------------------
  // Crypto helpers
  // -------------------------------------------------------------------
  void randomBytes(uint8_t *out, size_t n) {
  #if defined(ESP32)
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(esp_random() & 0xff);
  #else
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(RANDOM_REG32 & 0xff);
  #endif
  }

  void randomHex(char *out, size_t hexLen) {
    static const char hex[] = "0123456789abcdef";
    size_t bytes = hexLen / 2;
    uint8_t buf[32];
    if (bytes > sizeof(buf)) bytes = sizeof(buf);
    randomBytes(buf, bytes);
    for (size_t i = 0; i < bytes; i++) {
      out[i*2  ] = hex[(buf[i] >> 4) & 0xf];
      out[i*2+1] = hex[ buf[i]       & 0xf];
    }
    out[hexLen] = 0;
  }

  bool b64encode(const uint8_t *in, size_t inLen, char *out, size_t outCap) {
    size_t written = 0;
    int rc = mbedtls_base64_encode((unsigned char*)out, outCap, &written, in, inLen);
    if (rc != 0) return false;
    out[written] = 0;
    return true;
  }

  bool b64decode(const char *in, uint8_t *out, size_t outCap, size_t *outLen) {
    return mbedtls_base64_decode(out, outCap, outLen,
      (const unsigned char*)in, strlen(in)) == 0;
  }

  // Constant-time compare.
  bool ctEqual(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
  }

  // PBKDF2-SHA256(pw, salt, iters) -> 32 bytes
  bool pbkdf2(const char *pw, const uint8_t *salt, size_t saltLen,
              uint32_t iters, uint8_t out[32]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_setup(&ctx, info, 1) != 0) { mbedtls_md_free(&ctx); return false; }
    int rc = mbedtls_pkcs5_pbkdf2_hmac(&ctx,
              (const unsigned char*)pw, strlen(pw),
              salt, saltLen, iters, 32, out);
    mbedtls_md_free(&ctx);
    return rc == 0;
  }

  // Encode "v1$<iters>$<salt_b64>$<hash_b64>" into g_hashBlob.
  bool encodeHashBlob(uint32_t iters, const uint8_t *salt, size_t saltLen,
                      const uint8_t *hash, size_t hashLen) {
    char saltB64[48], hashB64[64];
    if (!b64encode(salt, saltLen, saltB64, sizeof(saltB64))) return false;
    if (!b64encode(hash, hashLen, hashB64, sizeof(hashB64))) return false;
    int n = snprintf(g_hashBlob, sizeof(g_hashBlob), "v1$%lu$%s$%s",
                     (unsigned long)iters, saltB64, hashB64);
    return n > 0 && (size_t)n < sizeof(g_hashBlob);
  }

  // Parse the stored blob back into iters/salt/hash. Returns false if malformed.
  bool decodeHashBlob(uint32_t &iters, uint8_t *salt, size_t saltCap, size_t &saltLen,
                      uint8_t *hash, size_t hashCap, size_t &hashLen) {
    if (g_hashBlob[0] == 0) return false;
    // Expect: v1$<iters>$<saltB64>$<hashB64>
    char tmp[HASH_BLOB_MAX + 1];
    strlcpy(tmp, g_hashBlob, sizeof(tmp));
    char *p = tmp;
    if (strncmp(p, "v1$", 3) != 0) return false;
    p += 3;
    char *itersEnd = strchr(p, '$'); if (!itersEnd) return false;
    *itersEnd = 0;
    iters = (uint32_t)strtoul(p, nullptr, 10);
    p = itersEnd + 1;
    char *saltEnd = strchr(p, '$'); if (!saltEnd) return false;
    *saltEnd = 0;
    if (!b64decode(p, salt, saltCap, &saltLen)) return false;
    p = saltEnd + 1;
    if (!b64decode(p, hash, hashCap, &hashLen)) return false;
    return true;
  }

  // -------------------------------------------------------------------
  // Session table
  // -------------------------------------------------------------------
  void purgeExpired(uint32_t now) {
    for (auto &s : g_sessions) {
      if (s.token[0] && (int32_t)(now - s.expiresAt) >= 0) s.token[0] = 0;
    }
  }

  // EVOLIGHTS-ANCHOR: session-lru-eviction
  // When the session table is full, evict the slot with the smallest
  // lastUsedAt (i.e. true LRU), not just slot 0. Old behaviour booted the
  // active admin out of session whenever a 9th login happened.
  const char* issueSession() {
    uint32_t now = millis();
    purgeExpired(now);
    for (auto &s : g_sessions) {
      if (s.token[0] == 0) {
        randomHex(s.token, TOKEN_LEN);
        s.expiresAt = now + SESSION_TTL_MS;
        s.lastUsedAt = now;
        return s.token;
      }
    }
    // Table full — evict the least-recently-used slot.
    Session *victim = &g_sessions[0];
    for (auto &s : g_sessions) {
      // (int32_t) cast to handle millis() wrap-around correctly.
      if ((int32_t)(s.lastUsedAt - victim->lastUsedAt) < 0) victim = &s;
    }
    randomHex(victim->token, TOKEN_LEN);
    victim->expiresAt = now + SESSION_TTL_MS;
    victim->lastUsedAt = now;
    return victim->token;
  }
  // EVOLIGHTS-ANCHOR: session-lru-eviction-end

  bool isValidSession(const char *token) {
    if (!token || !*token) return false;
    uint32_t now = millis();
    for (auto &s : g_sessions) {
      if (s.token[0] && (int32_t)(now - s.expiresAt) < 0
          && strncmp(s.token, token, TOKEN_LEN) == 0) {
        s.lastUsedAt = now;   // touch for LRU
        return true;
      }
    }
    return false;
  }

  void revokeSession(const char *token) {
    if (!token || !*token) return;
    for (auto &s : g_sessions) {
      if (s.token[0] && strncmp(s.token, token, TOKEN_LEN) == 0) s.token[0] = 0;
    }
  }

  // -------------------------------------------------------------------
  // Request introspection
  // -------------------------------------------------------------------
  // EVOLIGHTS-ANCHOR: cookie-parse-anchored
  // Earlier version used `c.indexOf("EVOAUTH=")` which would match the
  // substring inside `EVOAUTHX=junk`. We now require the marker to be at the
  // start of the cookie header OR preceded by "; ", per RFC 6265 cookie
  // formatting.
  String extractToken(AsyncWebServerRequest *request) {
    // 1. Authorization: Bearer <token>
    if (request->hasHeader(F("Authorization"))) {
      String h = request->getHeader(F("Authorization"))->value();
      if (h.startsWith(F("Bearer "))) return h.substring(7);
    }
    // 2. X-EvoLights-Token: <token>
    if (request->hasHeader(F("X-EvoLights-Token"))) {
      return request->getHeader(F("X-EvoLights-Token"))->value();
    }
    // 3. Cookie: EVOAUTH=<token>  (anchored to start-of-string OR "; ")
    if (request->hasHeader(F("Cookie"))) {
      String c = request->getHeader(F("Cookie"))->value();
      int i = 0;
      int found = -1;
      while (i >= 0 && (size_t)i < (size_t)c.length()) {
        i = c.indexOf(F("EVOAUTH="), i);
        if (i < 0) break;
        bool atStart = (i == 0);
        bool afterDelim = (i >= 2 && c.charAt(i - 1) == ' ' && c.charAt(i - 2) == ';');
        if (atStart || afterDelim) { found = i; break; }
        i += 1; // keep searching past this false hit
      }
      if (found >= 0) {
        int end = c.indexOf(';', found + 8);
        String t = end < 0 ? c.substring(found + 8) : c.substring(found + 8, end);
        t.trim();
        return t;
      }
    }
    return String();
  }
  // EVOLIGHTS-ANCHOR: cookie-parse-anchored-end

  // EVOLIGHTS-ANCHOR: cloud-token-loopback-only
  // The cloud-trusted token is meant to be used ONLY by the cloud_relay
  // usermod, which dispatches MQTT-originated commands into the local HTTP
  // stack via http://127.0.0.1<path>. If a request carrying the token arrives
  // from any non-loopback peer, refuse — that's either a leaked-token replay
  // from the LAN or an attacker who guessed the in-RAM token.
  // The 0.0.0.0 case covers some ESPAsyncWebServer code paths where the peer
  // address isn't populated yet (e.g. early in the handshake); in those cases
  // we play it safe and treat the request as untrusted, so we still reject.
  bool isLoopbackPeer(AsyncWebServerRequest *request) {
    if (!request || !request->client()) return false;
    IPAddress ip = request->client()->remoteIP();
    return ip == IPAddress(127, 0, 0, 1);
  }
  // EVOLIGHTS-ANCHOR: cloud-token-loopback-only-end

  // -------------------------------------------------------------------
  // HTML pages — kept inline to avoid touching the html_*.h build pipeline.
  // -------------------------------------------------------------------
  const char PAGE_SETUP[] PROGMEM = R"HTML(<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EvoLights Setup</title>
<style>
body{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1c1c1c;padding:32px;border-radius:12px;width:340px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{margin:0 0 8px;font-size:22px;color:#7cf}
p{color:#aaa;font-size:14px;margin:0 0 20px}
label{display:block;margin:12px 0 4px;font-size:13px;color:#bbb}
input{width:100%;box-sizing:border-box;padding:10px;background:#262626;border:1px solid #333;color:#eee;border-radius:6px;font-size:14px}
button{width:100%;margin-top:20px;padding:12px;background:#7cf;color:#000;border:0;border-radius:6px;font-weight:600;cursor:pointer;font-size:14px}
.err{color:#f77;font-size:13px;margin-top:12px;min-height:18px}
</style></head><body>
<form class="card" onsubmit="return go(event)">
<h1>Welcome to EvoLights</h1>
<p>Create your local administrator account. You'll use it to access this device's web interface.</p>
<label>Username</label><input id="u" autocomplete="username" required minlength="3" maxlength="32">
<label>Password</label><input id="p" type="password" autocomplete="new-password" required minlength="8" maxlength="64">
<label>Confirm password</label><input id="p2" type="password" autocomplete="new-password" required minlength="8" maxlength="64">
<button type="submit">Create account</button>
<div class="err" id="e"></div>
</form>
<script>
async function go(e){e.preventDefault();var u=document.getElementById('u').value,p=document.getElementById('p').value,p2=document.getElementById('p2').value;
if(p!==p2){document.getElementById('e').textContent='Passwords do not match';return false}
try{var r=await fetch('/auth/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
if(r.ok){location.href='/'}else{var t=await r.text();document.getElementById('e').textContent=t||'Setup failed'}}catch(x){document.getElementById('e').textContent=x.message}return false}
</script></body></html>)HTML";

  const char PAGE_LOGIN[] PROGMEM = R"HTML(<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EvoLights Sign in</title>
<style>
body{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1c1c1c;padding:32px;border-radius:12px;width:320px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{margin:0 0 20px;font-size:22px;color:#7cf}
label{display:block;margin:12px 0 4px;font-size:13px;color:#bbb}
input{width:100%;box-sizing:border-box;padding:10px;background:#262626;border:1px solid #333;color:#eee;border-radius:6px;font-size:14px}
button{width:100%;margin-top:20px;padding:12px;background:#7cf;color:#000;border:0;border-radius:6px;font-weight:600;cursor:pointer;font-size:14px}
.err{color:#f77;font-size:13px;margin-top:12px;min-height:18px}
</style></head><body>
<form class="card" onsubmit="return go(event)">
<h1>EvoLights</h1>
<label>Username</label><input id="u" autocomplete="username" required>
<label>Password</label><input id="p" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
<div class="err" id="e"></div>
</form>
<script>
async function go(e){e.preventDefault();
try{var r=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
if(r.ok){location.href='/'}else{document.getElementById('e').textContent='Invalid credentials'}}catch(x){document.getElementById('e').textContent=x.message}return false}
</script></body></html>)HTML";

  // -------------------------------------------------------------------
  // The single AuthGate handler — registered before initServer().
  // -------------------------------------------------------------------
  class AuthGate : public AsyncWebHandler {
   public:
    bool canHandle(AsyncWebServerRequest *request) override {
      // OPTIONS is for CORS preflight — let WLED's own handler answer it.
      if (request->method() == HTTP_OPTIONS) return false;
      const String &u = request->url();
      if (isPublicPath(u)) return false;

      // First-boot bypass: while the device is in its own AP and has not yet
      // joined a WiFi network, only the WiFi-setup-related routes are open.
      // Everything else (edit, OTA, JSON cfg, etc.) still requires auth — the
      // operator should not be able to do dangerous things before they create
      // an admin account. See `ap-setup-allowlist` anchor above.
      if (apActive && !WLED_WIFI_CONFIGURED) {
        if (isWifiSetupAllowed(u)) return false;
        return true;
      }

      // First-time setup: only /auth/setup is reachable.
      if (!isConfigured()) return true;

      // Local auth disabled AND cloud bypass enabled: trust everything that
      // comes through (i.e. requests delivered by the cloud relay) — but only
      // from loopback (127.0.0.1), per cloud-token-loopback-only.
      if (!g_localEnabled && g_cloudBypassEnabled && isLoopbackPeer(request)) return false;

      if (isAuthorized(request)) return false;
      return true;
    }

    void handleRequest(AsyncWebServerRequest *request) override {
      if (!isConfigured()) {
        // Send the setup page directly so the user lands somewhere useful.
        request->send_P(200, F("text/html"), PAGE_SETUP);
        return;
      }
      // Browser? send login page. API client? 401 JSON.
      if (request->hasHeader(F("Accept"))
          && request->getHeader(F("Accept"))->value().indexOf(F("text/html")) >= 0) {
        request->send_P(401, F("text/html"), PAGE_LOGIN);
      } else {
        request->send(401, F("application/json"), F("{\"error\":\"unauthorized\"}"));
      }
    }
  };

  AuthGate *g_gate = nullptr;

  // -------------------------------------------------------------------
  // /auth/* route registration
  // -------------------------------------------------------------------
  void parseJsonBody(AsyncWebServerRequest *request, uint8_t *data, size_t len,
                     String &username, String &password) {
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, data, len)) return;
    username = doc["username"] | "";
    password = doc["password"] | "";
  }

  void registerRoutes(AsyncWebServer &server) {
    // GET setup page (only useful when unconfigured; AuthGate also serves it).
    server.on("/auth/setup", HTTP_GET, [](AsyncWebServerRequest *request) {
      if (isConfigured()) {
        request->redirect("/auth/login");
        return;
      }
      request->send_P(200, F("text/html"), PAGE_SETUP);
    });

    // POST setup — create the first account. Refused if one already exists.
    auto setupBodyHandler = [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      // EVOLIGHTS-ANCHOR: auth-setup-presence
      // Physical-presence proxy. If the device has been online for longer than
      // SETUP_PRESENCE_WINDOW_MS and is NOT in AP mode, refuse setup. The
      // legitimate first-time user is either joining the device's AP or freshly
      // power-cycling. An attacker who hits an already-running unconfigured
      // device over the LAN does NOT get to claim it.
      if (millis() > SETUP_PRESENCE_WINDOW_MS && !apActive) {
        request->send(403, F("text/plain"),
          F("physical presence required: power-cycle the device before running setup"));
        return;
      }
      // EVOLIGHTS-ANCHOR: auth-setup-presence-end

      // EVOLIGHTS-ANCHOR: auth-setup-mutex-acquire
      // Single-flight guard. Two clients racing on /auth/setup must not both
      // pass the isConfigured() check. The SetupGuard RAII helper clears the
      // flag on every exit path including early returns.
      SetupGuard guard;
      if (g_setupInProgress || isConfigured()) {
        request->send(409, F("text/plain"), F("already configured or setup in progress"));
        return;
      }
      g_setupInProgress = true;
      guard.acquired = true;
      // EVOLIGHTS-ANCHOR: auth-setup-mutex-acquire-end

      String u, p;
      parseJsonBody(request, data, len, u, p);
      if (u.length() < 3 || p.length() < 8) {
        request->send(400, F("text/plain"), F("username >=3 chars, password >=8 chars"));
        return;
      }
      if (!setCredentials(u, p)) {
        request->send(500, F("text/plain"), F("failed to store credentials"));
        return;
      }
      // Auto-login the new admin so they don't get bounced back to /auth/login.
      const char *tok = issueSession();
      AsyncWebServerResponse *resp = request->beginResponse(200, F("application/json"),
        String("{\"token\":\"") + tok + "\"}");
      resp->addHeader(F("Set-Cookie"),
        String("EVOAUTH=") + tok + "; Path=/; Max-Age=604800; SameSite=Lax; HttpOnly");
      request->send(resp);
    };
    server.on("/auth/setup", HTTP_POST, [](AsyncWebServerRequest*){}, nullptr, setupBodyHandler);

    // GET login page.
    server.on("/auth/login", HTTP_GET, [](AsyncWebServerRequest *request) {
      if (!isConfigured()) {
        request->redirect("/auth/setup");
        return;
      }
      request->send_P(200, F("text/html"), PAGE_LOGIN);
    });

    // POST login -> session cookie + token.
    auto loginBodyHandler = [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      String u, p;
      parseJsonBody(request, data, len, u, p);
      if (!verifyPassword(u, p)) {
        request->send(401, F("application/json"), F("{\"error\":\"invalid_credentials\"}"));
        return;
      }
      const char *tok = issueSession();
      AsyncWebServerResponse *resp = request->beginResponse(200, F("application/json"),
        String("{\"token\":\"") + tok + "\"}");
      resp->addHeader(F("Set-Cookie"),
        String("EVOAUTH=") + tok + "; Path=/; Max-Age=604800; SameSite=Lax; HttpOnly");
      request->send(resp);
    };
    server.on("/auth/login", HTTP_POST, [](AsyncWebServerRequest*){}, nullptr, loginBodyHandler);

    // POST logout — revoke session.
    server.on("/auth/logout", HTTP_POST, [](AsyncWebServerRequest *request) {
      String t = extractToken(request);
      revokeSession(t.c_str());
      AsyncWebServerResponse *resp = request->beginResponse(200, F("application/json"), F("{\"ok\":true}"));
      resp->addHeader(F("Set-Cookie"), F("EVOAUTH=; Path=/; Max-Age=0"));
      request->send(resp);
    });

    // GET /auth/status — public endpoint so the mobile app can probe a device.
    server.on("/auth/status", HTTP_GET, [](AsyncWebServerRequest *request) {
      String body = String(F("{\"configured\":")) + (isConfigured() ? "true" : "false")
                  + F(",\"local\":") + (g_localEnabled ? "true" : "false")
                  + F(",\"cloud\":") + (g_cloudBypassEnabled ? "true" : "false")
                  + F(",\"product\":\"EvoLights\"}");
      request->send(200, F("application/json"), body);
    });
  }

} // anonymous namespace

// =====================================================================
// Public API
// =====================================================================
bool isConfigured() { return g_username[0] != 0 && g_hashBlob[0] != 0; }
bool isLocalEnabled() { return g_localEnabled; }
bool isCloudBypassEnabled() { return g_cloudBypassEnabled; }

void setCloudBypassEnabled(bool enabled) { g_cloudBypassEnabled = enabled; }

const char* cloudTrustedToken() { return g_cloudToken; }

bool isAuthorized(AsyncWebServerRequest *request) {
  // EVOLIGHTS-ANCHOR: cloud-pairing-session-only
  // /cloud/pair and /cloud/unpair manipulate cloud-pairing state; they MUST
  // require a real local session. The cloud-trusted token (which exists for
  // MQTT->loopback dispatch) must NOT satisfy these endpoints — otherwise a
  // remote actor with the token could wipe pairing or re-pair the device.
  const String &url = request ? request->url() : String();
  bool isPairingMutator = (url == F("/cloud/pair") || url == F("/cloud/unpair"));
  // EVOLIGHTS-ANCHOR: cloud-pairing-session-only-end

  // Cloud-trusted token: only honoured for loopback peers AND not for the
  // pairing endpoints (see anchors above).
  if (!isPairingMutator && g_cloudBypassEnabled && g_cloudToken[0] && isLoopbackPeer(request)) {
    String t = extractToken(request);
    if (t.length() == TOKEN_LEN && strncmp(t.c_str(), g_cloudToken, TOKEN_LEN) == 0) return true;
  }
  if (!g_localEnabled) {
    // Local auth turned off and no cloud bypass token matched — treat as
    // unauthorized to avoid silently exposing the UI on the LAN.
    return false;
  }
  String t = extractToken(request);
  return t.length() == TOKEN_LEN && isValidSession(t.c_str());
}

bool setCredentials(const String &user, const String &pw) {
  uint8_t salt[16], hash[32];
  randomBytes(salt, sizeof(salt));
  if (!pbkdf2(pw.c_str(), salt, sizeof(salt), PBKDF2_ITERS, hash)) return false;
  if (!encodeHashBlob(PBKDF2_ITERS, salt, sizeof(salt), hash, sizeof(hash))) return false;
  strlcpy(g_username, user.c_str(), sizeof(g_username));
  // Persist immediately. fcn_declare.h provides serializeConfigSec().
  serializeConfigSec();
  return true;
}

// EVOLIGHTS-ANCHOR: login-timing-oracle-verify
// verifyPassword runs PBKDF2 unconditionally — even when the username is
// unknown, we hash the supplied password against a fixed dummy salt and
// compare against a fixed dummy hash. The function thus takes the same
// wall-clock time regardless of whether the user exists, denying the attacker
// a username-enumeration oracle.
bool verifyPassword(const String &user, const String &pw) {
  if (!isConfigured()) {
    // Even before any account exists we burn a PBKDF2 cycle to keep the
    // pre-/post-setup latency profile indistinguishable.
    uint8_t scratch[32];
    if (g_dummyReady) (void)pbkdf2(pw.c_str(), g_dummySalt, sizeof(g_dummySalt), PBKDF2_ITERS, scratch);
    return false;
  }

  bool userMatches = (strncmp(g_username, user.c_str(), USERNAME_MAX) == 0);

  uint32_t iters; uint8_t salt[32], hash[32]; size_t saltLen = 0, hashLen = 0;
  bool blobOk = decodeHashBlob(iters, salt, sizeof(salt), saltLen, hash, sizeof(hash), hashLen);

  // Always run PBKDF2. If the user matches and the blob parsed, run against
  // the real salt+iters; otherwise run against the dummy with PBKDF2_ITERS so
  // an attacker can't distinguish the two cases by latency.
  uint8_t check[32] = {0};
  bool pbkOk;
  if (userMatches && blobOk && hashLen == 32) {
    pbkOk = pbkdf2(pw.c_str(), salt, saltLen, iters, check);
  } else {
    pbkOk = g_dummyReady
              ? pbkdf2(pw.c_str(), g_dummySalt, sizeof(g_dummySalt), PBKDF2_ITERS, check)
              : false;
  }

  // ctEqual against the real hash if possible, else against the dummy hash.
  // Either way, a single constant-time compare runs.
  const uint8_t *expect = (userMatches && blobOk && hashLen == 32) ? hash : g_dummyHash;
  bool match = pbkOk && ctEqual(check, expect, 32);

  // Final answer: only true if the user actually exists, the blob was OK,
  // and the real hash matched. The dummy comparison's result is discarded.
  return userMatches && blobOk && hashLen == 32 && match;
}
// EVOLIGHTS-ANCHOR: login-timing-oracle-verify-end

bool readFromWsec(const JsonObject &root) {
  JsonVariantConst auth = root[F("evoauth")];
  if (auth.isNull()) return false;
  const char *u = auth["u"] | "";
  const char *h = auth["h"] | "";
  bool en = auth["en"] | true;
  strlcpy(g_username, u, sizeof(g_username));
  strlcpy(g_hashBlob, h, sizeof(g_hashBlob));
  g_localEnabled = en;
  return true;
}

void writeToWsec(JsonObject &root) {
  JsonObject auth = root.createNestedObject(F("evoauth"));
  auth[F("u")]  = g_username;
  auth[F("h")]  = g_hashBlob;
  auth[F("en")] = g_localEnabled;
}

void init(AsyncWebServer &server) {
  randomHex(g_cloudToken, TOKEN_LEN);    // fresh token every boot

  // Pre-compute a dummy PBKDF2 (salt+hash) used by verifyPassword to keep the
  // unknown-user path equal-time to the known-user path. Done once at boot;
  // the dummy password is itself random so the dummy hash is unguessable.
  randomBytes(g_dummySalt, sizeof(g_dummySalt));
  uint8_t dummyPw[16];
  randomBytes(dummyPw, sizeof(dummyPw));
  char dummyPwHex[33];
  randomHex(dummyPwHex, 32);
  g_dummyReady = pbkdf2(dummyPwHex, g_dummySalt, sizeof(g_dummySalt), PBKDF2_ITERS, g_dummyHash);

  if (!g_gate) g_gate = new AuthGate();
  server.addHandler(g_gate);             // registered FIRST — wins canHandle()
  registerRoutes(server);
  Serial.printf("[EvoAuth] init done; configured=%d localEnabled=%d dummyReady=%d\n",
                (int)isConfigured(), (int)g_localEnabled, (int)g_dummyReady);
}

} // namespace EvoAuth
