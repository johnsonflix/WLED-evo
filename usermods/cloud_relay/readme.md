# EvoLights Cloud Relay

ESP32-only WLED-EvoLights usermod that establishes an outbound MQTT-over-TLS
connection to the EvoLights cloud panel so the mobile app can control the
device from outside the home network without any port-forwarding.

## How it works

1. **Pairing**: the mobile app issues a 6-digit code via the cloud API, then
   POSTs `{ "code": "ABC123", "broker": "mqtts://...", "ca_cert": "..." }`
   to `/cloud/pair` on this device while on the same LAN. The device redeems
   the code with the cloud, receives per-device MQTT credentials, persists
   them to `wsec.json`, and connects to the broker.

2. **Steady state**: the device subscribes to `evolights/<device_id>/cmd` and
   `evolights/<device_id>/ota`, and publishes state changes to
   `evolights/<device_id>/state`. The connection stays open; the broker pushes
   commands down on demand.

3. **Local-auth bypass**: when a command arrives over MQTT, the relay injects
   it into the local HTTP stack with the cloud-trusted token from the EvoAuth
   module. That token bypasses the local auth gate, so cloud commands work
   even when local auth is enabled.

## Build

Add to your platformio_override.ini:

```ini
custom_usermods = cloud_relay
build_flags = -D USERMOD_EVOLIGHTS_CLOUD_RELAY
```

## HTTP endpoints (registered in setup())

- `POST /cloud/pair`     redeem pairing code, store credentials, connect
- `POST /cloud/unpair`   forget credentials, disconnect
- `GET  /cloud/status`   `{ paired, connected, broker, device_id }`

All three require local auth (the EvoAuth gate sees them).

## MQTT topics

- `evolights/<device_id>/cmd`   `{path,method,body}` JSON requests, replied to on `/state`
- `evolights/<device_id>/state` device-published state and command responses
- `evolights/<device_id>/ota`   signed firmware manifest (handled in a follow-up)
- `evolights/<device_id>/log`   opt-in debug logs

## Status

Initial scaffold — JSON API proxy and pairing are live; OTA flow is stubbed.
