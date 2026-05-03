#pragma once

/*
 * EvoLights signed-OTA verifier (ESP32 only).
 *
 * Manifest format (received over MQTT on evolights/<device_id>/ota):
 *   { "version": "0.1.0+ev3", "url": "https://...bin", "sig": "<base64>", "sha256": "<hex>" }
 *
 * Trust chain:
 *   - The Ed25519 PUBLIC KEY is compiled into the firmware as OTA_PUBKEY_B64
 *     (32 raw bytes, base64-encoded). The matching PRIVATE key lives only on
 *     the cloud panel host.
 *   - Signature is computed by the cloud over `version|url|sha256`.
 *   - On receipt the device verifies the signature first, THEN downloads the
 *     binary, computes its sha256, checks the hash matches, and only then
 *     calls Update.write/end. The Update class also performs ESP-IDF
 *     bootloader signature verification (if enabled at flash time).
 *
 * If sig fails, downloaded sha256 mismatches, or HTTPS fails: refuse to flash.
 */

#include <Arduino.h>

namespace EvoLights::OTA {

  // Process one manifest message. Logs and returns false on any failure.
  // On success, the device flashes and reboots — function does not return.
  bool processManifest(const char *json, size_t len);

  // For tools/verify-evolights-integration.sh to grep.
  extern const char* const OTA_PUBKEY_B64_MARKER;
}
