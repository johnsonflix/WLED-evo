#ifndef WLED_CLOUD_AUTH_H
#define WLED_CLOUD_AUTH_H

/*
 * EvoLights authentication layer.
 *
 * Sits in front of the WLED web UI as a single AsyncWebHandler that gets
 * registered BEFORE initServer() builds the route table. Because
 * ESPAsyncWebServer dispatches to the first handler whose canHandle() returns
 * true, our gate gets first dibs on every request and either:
 *   - says "I do not handle this" and lets the existing WLED route run, OR
 *   - says "I handle this" and returns a 401 / login redirect.
 *
 * No per-route patches required.
 *
 * Two trust paths:
 *   1. Local: bearer token (Authorization header) or cookie set by /auth/login.
 *      Sessions live in RAM; lost on reboot (acceptable trade-off).
 *      Password is PBKDF2-SHA256 hashed in wsec.json.
 *   2. Cloud: requests carrying the in-RAM cloud-trusted token are bypassed.
 *      The cloud_relay usermod uses this when it dispatches an MQTT command
 *      into the local HTTP stack via 127.0.0.1. The gate ALSO requires the
 *      request to originate from the loopback address (so a LAN attacker who
 *      learns/guesses the token cannot use it) — see anchor
 *      `cloud-token-loopback-only` in wled_cloud_auth.cpp.
 *
 * Persistence: credentials live in wsec.json (LittleFS), which is preserved
 * across OTA updates because OTA only flashes the firmware partition.
 */

#include <Arduino.h>
// JsonObject is a typedef in ArduinoJson v6, so it can't be forward-declared
// with `class JsonObject`. Pull in the wled-vendored ArduinoJson header so
// the type is fully defined for our wsec.json hook signatures.
#include "src/dependencies/json/ArduinoJson-v6.h"

class AsyncWebServer;
class AsyncWebServerRequest;

namespace EvoAuth {

  // Sized to fit one bcrypt-style stored hash blob (salt + iters + hash, base64'd).
  constexpr size_t USERNAME_MAX = 32;
  constexpr size_t PASSWORD_MAX = 64;
  constexpr size_t HASH_BLOB_MAX = 160;        // pbkdf2-sha256 output, b64'd
  constexpr size_t TOKEN_LEN     = 32;         // hex chars (16 random bytes)
  constexpr uint32_t SESSION_TTL_MS = 7 * 24UL * 3600UL * 1000UL;   // 7 days
  constexpr uint8_t  MAX_SESSIONS = 8;
  // EVOLIGHTS-ANCHOR: pbkdf2-iters
  // Bumped from 4096 (2010s-grade) to 50000. On an ESP32 @ 240MHz this targets
  // ~600ms login latency, which is acceptable for a one-time login. If a future
  // platform measures slower than 500ms, drop this back to the highest value
  // that stays under 500ms. Stored hashes embed the iteration count
  // (`v1$<iters>$<salt>$<hash>`), so bumping this constant does NOT invalidate
  // existing accounts — they keep working with their original iter count
  // until the user changes their password.
  constexpr uint32_t PBKDF2_ITERS = 50000;
  // EVOLIGHTS-ANCHOR: pbkdf2-iters-end

  // Window after boot during which /auth/setup will accept a request from
  // outside AP mode. Used as a physical-presence proxy: the legitimate first
  // user is power-cycling or freshly-flashing the device, not an attacker on
  // a long-online LAN. See anchor `auth-setup-presence` in wled_cloud_auth.cpp.
  constexpr uint32_t SETUP_PRESENCE_WINDOW_MS = 5UL * 60UL * 1000UL;

  // Called once from setup() BEFORE initServer().
  // Registers the AuthGate handler and the /auth/* routes.
  void init(AsyncWebServer &server);

  // True if a username+password has been configured.
  bool isConfigured();

  // True if local auth is enabled (master switch from settings).
  bool isLocalEnabled();

  // True if cloud-trusted bypass is enabled (cloud_relay usermod sets this).
  bool isCloudBypassEnabled();
  void setCloudBypassEnabled(bool enabled);

  // Returns the in-RAM cloud-trusted token. cloud_relay usermod uses this when
  // injecting MQTT-originated requests so they bypass local auth.
  // Token is generated at boot, never persisted, never exposed via HTTP.
  const char* cloudTrustedToken();

  // wsec.json hooks — called by cfg.cpp.
  bool readFromWsec(const JsonObject &root);
  void writeToWsec(JsonObject &root);

  // Programmatic credential management (used by /auth/setup and /auth/password).
  // Returns true on success. Hashes pw with PBKDF2-SHA256 + per-account salt.
  bool setCredentials(const String &user, const String &pw);
  bool verifyPassword(const String &user, const String &pw);

  // True if the request carries a valid local session OR cloud-trusted token.
  // The cloud-trusted token is only honoured for requests from 127.0.0.1 and
  // is REFUSED for /cloud/pair and /cloud/unpair (those endpoints require a
  // real local session — see `cloud-pairing-session-only` in the .cpp).
  bool isAuthorized(AsyncWebServerRequest *request);
}

#endif // WLED_CLOUD_AUTH_H
