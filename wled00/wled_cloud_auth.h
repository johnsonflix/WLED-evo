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
 *      into the local HTTP stack.
 *
 * Persistence: credentials live in wsec.json (LittleFS), which is preserved
 * across OTA updates because OTA only flashes the firmware partition.
 */

#include <Arduino.h>

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
  constexpr uint16_t PBKDF2_ITERS = 4096;      // tuned for ESP32 ~50ms

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
  bool readFromWsec(const class JsonObject &root);
  void writeToWsec(class JsonObject &root);

  // Programmatic credential management (used by /auth/setup and /auth/password).
  // Returns true on success. Hashes pw with PBKDF2-SHA256 + per-account salt.
  bool setCredentials(const String &user, const String &pw);
  bool verifyPassword(const String &user, const String &pw);

  // True if the request carries a valid local session OR cloud-trusted token.
  bool isAuthorized(AsyncWebServerRequest *request);
}

#endif // WLED_CLOUD_AUTH_H
