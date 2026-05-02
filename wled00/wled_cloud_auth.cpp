#include "wled.h"
#include "wled_cloud_auth.h"

#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
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
  };
  Session g_sessions[MAX_SESSIONS] = {};

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
              uint16_t iters, uint8_t out[32]) {
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
  bool encodeHashBlob(uint16_t iters, const uint8_t *salt, size_t saltLen,
                      const uint8_t *hash, size_t hashLen) {
    char saltB64[48], hashB64[64];
    if (!b64encode(salt, saltLen, saltB64, sizeof(saltB64))) return false;
    if (!b64encode(hash, hashLen, hashB64, sizeof(hashB64))) return false;
    int n = snprintf(g_hashBlob, sizeof(g_hashBlob), "v1$%u$%s$%s",
                     (unsigned)iters, saltB64, hashB64);
    return n > 0 && (size_t)n < sizeof(g_hashBlob);
  }

  // Parse the stored blob back into iters/salt/hash. Returns false if malformed.
  bool decodeHashBlob(uint16_t &iters, uint8_t *salt, size_t saltCap, size_t &saltLen,
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
    iters = (uint16_t)atoi(p);
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

  const char* issueSession() {
    uint32_t now = millis();
    purgeExpired(now);
    for (auto &s : g_sessions) {
      if (s.token[0] == 0) {
        randomHex(s.token, TOKEN_LEN);
        s.expiresAt = now + SESSION_TTL_MS;
        return s.token;
      }
    }
    // Table full — evict oldest by recycling slot 0.
    randomHex(g_sessions[0].token, TOKEN_LEN);
    g_sessions[0].expiresAt = now + SESSION_TTL_MS;
    return g_sessions[0].token;
  }

  bool isValidSession(const char *token) {
    if (!token || !*token) return false;
    uint32_t now = millis();
    for (auto &s : g_sessions) {
      if (s.token[0] && (int32_t)(now - s.expiresAt) < 0
          && strncmp(s.token, token, TOKEN_LEN) == 0) {
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
    // 3. Cookie: EVOAUTH=<token>
    if (request->hasHeader(F("Cookie"))) {
      String c = request->getHeader(F("Cookie"))->value();
      int i = c.indexOf(F("EVOAUTH="));
      if (i >= 0) {
        int end = c.indexOf(';', i);
        return end < 0 ? c.substring(i + 8) : c.substring(i + 8, end);
      }
    }
    return String();
  }

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
      // joined a WiFi network, the user is presumed authorized (they have
      // physical proximity). Lets them reach WLED's WiFi setup pages so they
      // can join their network — auth setup happens after that.
      if (apActive && !WLED_WIFI_CONFIGURED) return false;

      // First-time setup: only /auth/setup is reachable.
      if (!isConfigured()) return true;

      // Local auth disabled AND cloud bypass enabled: trust everything that
      // comes through (i.e. requests delivered by the cloud relay).
      if (!g_localEnabled && g_cloudBypassEnabled) return false;

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
      if (isConfigured()) {
        request->send(409, F("text/plain"), F("already configured"));
        return;
      }
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
  // Cloud-trusted token always wins (used by cloud_relay usermod internally).
  if (g_cloudBypassEnabled && g_cloudToken[0]) {
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

bool verifyPassword(const String &user, const String &pw) {
  if (!isConfigured()) return false;
  if (strncmp(g_username, user.c_str(), USERNAME_MAX) != 0) return false;
  uint16_t iters; uint8_t salt[32], hash[32]; size_t saltLen = 0, hashLen = 0;
  if (!decodeHashBlob(iters, salt, sizeof(salt), saltLen, hash, sizeof(hash), hashLen)) return false;
  if (hashLen != 32) return false;
  uint8_t check[32];
  if (!pbkdf2(pw.c_str(), salt, saltLen, iters, check)) return false;
  return ctEqual(check, hash, 32);
}

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
  if (!g_gate) g_gate = new AuthGate();
  server.addHandler(g_gate);             // registered FIRST — wins canHandle()
  registerRoutes(server);
  Serial.printf("[EvoAuth] init done; configured=%d localEnabled=%d\n",
                (int)isConfigured(), (int)g_localEnabled);
}

} // namespace EvoAuth
