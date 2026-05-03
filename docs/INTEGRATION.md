# EvoLights Integration Guide

> One document. The iOS coding agent should be able to read this once and
> build a working SwiftUI app against the EvoLights system end-to-end.
>
> All endpoints below are derived directly from the source. Where the source
> contradicts the original outline, the source wins and the deviation is
> called out inline.

---

## 0. Overview

EvoLights is a smart-light platform built on a fork of WLED for ESP32. Each
device is a regular WLED controller plus two EvoLights additions:

1. A local authentication gate (username + password) so the device's web /
   JSON API isn't open to anyone on the LAN.
2. An outbound MQTT bridge (the `cloud_relay` usermod) that lets a paid
   cloud panel relay commands to the device from anywhere on the internet
   without requiring port forwarding at the user's home.

The mobile app talks to two distinct surfaces:

```
   ┌──────────────────┐          local LAN          ┌────────────────────┐
   │   iOS / SwiftUI  │ ─── HTTP /json/* ──────────▶│ WLED-EvoLights     │
   │       app        │ ◀── WS state push  ─────────│ device on ESP32    │
   │                  │                             │ (mDNS _wled._tcp)  │
   │                  │                             └─────────┬──────────┘
   │                  │                                       │ outbound
   │                  │                                       │ MQTT
   │                  │   internet                            ▼
   │                  │ ──── HTTPS /v1/* ─────────▶ ┌──────────────────┐
   │                  │ ◀──────────────────────────│ EvoLights cloud  │
   │                  │                            │ (Fastify + PG +  │
   │                  │                            │  Mosquitto)      │
   └──────────────────┘                            └──────────────────┘
```

Two control paths exist and they are NOT interchangeable from the firmware's
point of view:

- **Local path** — free, works only when the phone and device are on the
  same network. Discovery via mDNS (`_wled._tcp` on port 80). Auth is the
  device's own username + password (a 7-day session token).
- **Cloud path** — requires an active subscription on the user's cloud
  account. The phone calls the cloud, which relays the command via MQTT to
  the device, which dispatches it back into its own local HTTP stack via
  loopback so the same JSON-API code path runs.

**Trust model in one paragraph.** The user's cloud account is gated by a
JWT (HS256, 7-day TTL, server-side revocable per user). Each paired device
gets its own per-device MQTT username and password (provisioned at pairing,
hashed with argon2, ACL-scoped to that device's topic prefix). The local
device's web/JSON API is gated by a per-device PBKDF2-SHA256 password hash,
held in the device's `wsec.json`. OTA firmware images are signed offline
with an Ed25519 keypair (private key on the cloud panel, public key
compiled into the firmware); the device verifies the signature before
flashing and refuses to downgrade. TLS to the broker is **not yet
implemented on the firmware side** — this is a deliberate, documented gap;
see Section 5.4.

---

## 1. Constants & Conventions

### 1.1 Production base URLs

The defaults the cloud falls back to when neither the runtime setting nor the
env var is set:

| Surface          | Default                                        | Configured by                                                       |
|------------------|------------------------------------------------|---------------------------------------------------------------------|
| Cloud API base   | `https://api.evolights.io`                     | Admin UI → Settings → Public → Public API URL (or `PUBLIC_API_URL`) |
| Web app          | `https://app.evolights.io`                     | Admin UI → Settings → Public → Public web URL (or `PUBLIC_WEB_URL`) |
| MQTT broker host | `mqtt.evolights.io`                            | Admin UI → Settings → Public → MQTT broker hostname (or `MQTT_PUBLIC_HOST`) |
| MQTT broker port | `8883` (TLS, public)                           | Admin UI → Settings → Public → MQTT broker port (or `MQTT_PUBLIC_PORT`) |
| Custom URL scheme| `evolights://`                                 | iOS app must register                                               |

> Operator note: env vars are first-boot defaults only. Once the api is up,
> the admin UI's Settings page is the source of truth — values stored in the
> `app_settings` table override the matching env var. No iOS-app changes are
> required when an operator rotates these; the same `/v1/me`, `/v1/devices`,
> `/v1/devices/redeem`, etc. endpoints respond with the current values.

> ⚠ These hostnames are placeholders the operator may not have stood up yet.
> Treat them as "fill these in at app launch / settings" — the SwiftUI app
> should read its API base URL from `Settings.bundle` (or a build-time
> `Info.plist` value) so QA can point staging vs prod without rebuilding.

### 1.2 HTTP conventions

| Item              | Value                                                                  |
|-------------------|------------------------------------------------------------------------|
| All cloud routes  | Prefixed with `/v1/`                                                   |
| Content-Type      | `application/json` (request and response)                              |
| Auth header       | `Authorization: Bearer <jwt>`                                          |
| Time format       | ISO 8601 in JSON, UNIX timestamp in JWT `iat`/`exp`                   |
| Error envelope    | `{"error": "snake_case_code", "details"?: any}`                        |
| Rate limit signal | `429 Too Many Requests` with `Retry-After` header                      |
| 5xx retry         | Exponential backoff; idempotent reads safe to retry                    |

### 1.3 CORS

The cloud API denies all cross-origin browser requests by default. The
SwiftUI app does NOT set an `Origin` header (native HTTP client), so CORS
is a non-issue for it. Don't try to `fetch()` from a browser dev page
against production unless the operator has added your origin to
`CORS_ORIGIN`.

---

## 2. Cloud account auth

All routes in this section live on the cloud panel.

### 2.1 Email / password registration

`POST /v1/auth/register`

```json
{ "email": "user@example.com", "password": "min8chars" }
```

| Status | Body                                                                       | Meaning                          |
|--------|----------------------------------------------------------------------------|----------------------------------|
| 201    | `{"token": "...", "user": {"id":"uuid", "email":"...", "created_at":"..."}}` | New account created              |
| 400    | `{"error":"invalid_payload", "details": {...}}`                            | Email malformed or password <8   |
| 409    | `{"error":"email_in_use"}`                                                 | Account already exists           |
| 429    | (rate limited)                                                             | 5/hr per IP cap                  |

The 201 response carries a JWT directly so the app can skip a follow-up
login round-trip.

### 2.2 Email / password login

`POST /v1/auth/login`

```json
{ "email": "user@example.com", "password": "..." }
```

| Status | Body                                                          | Meaning                                |
|--------|---------------------------------------------------------------|----------------------------------------|
| 200    | `{"token": "...", "user": {"id":"uuid", "email":"..."}}`      | Success                                |
| 400    | `{"error":"invalid_payload"}`                                 | Schema invalid                         |
| 401    | `{"error":"invalid_credentials"}`                             | Wrong email or wrong password          |
| 429    | (rate limited)                                                | 5/15min per IP                         |

The 401 response is returned even when the email is unknown, and the
server burns a constant-time argon2 hash on the unknown-email branch so an
attacker can't measure timing to enumerate registered emails. OAuth-only
accounts (signed up via Apple/Google with no local password) also return
401 here — the client should suggest "try Sign in with Apple/Google"
on a 401 if the user previously used SSO.

### 2.3 Sign in with Apple

`POST /v1/auth/apple`

Native iOS flow:

1. Use `AuthenticationServices` framework. Request `.email` and `.fullName`
   scopes the **first time only** (Apple drops `email`/`name` on subsequent
   sign-ins; cache them locally if you want them).
2. From the `ASAuthorizationAppleIDCredential`, take `identityToken: Data`.
3. Decode it as UTF-8 and POST it as `id_token`.

```json
{ "id_token": "<JWT from Apple>", "nonce": "<optional, must match the one passed to Apple>" }
```

| Status | Body                                                          | Meaning                                                     |
|--------|---------------------------------------------------------------|-------------------------------------------------------------|
| 200    | `{"token": "...", "user": {"id":"uuid", "email":"..."}}`      | Existing user, or freshly linked, or freshly created        |
| 400    | `{"error":"invalid_payload"}`                                 | Missing/oversized id_token                                  |
| 401    | `{"error":"invalid_id_token"}`                                | Apple JWKS verification failed (expired, wrong aud, etc.)   |
| 409    | `{"error":"account_link_conflict"}`                           | Email exists, already bound to a different `apple_sub` or   |
|        |                                                               | `google_sub`. Surface a message that the user should sign in|
|        |                                                               | with the original method.                                   |
| 503    | `{"error":"apple_not_configured"}`                            | Server has no `APPLE_CLIENT_ID` set                         |
| 429    | (rate limited)                                                | 30/15min per IP                                             |

**Apple private-relay emails.** When the user picks "Hide my email", Apple
delivers an `@privaterelay.appleid.com` email on first sign-in only. If
Apple delivers no email at all on subsequent logins (which it can), the
backend synthesizes a stable placeholder of the form
`<sub>@apple.users.noreply.evolights.io` for the unique-email constraint.
The app should not show that synthetic value to the user; instead show the
display email from `ASAuthorizationAppleIDCredential.email` if present
(cache it the first time), or fall back to "Apple ID user" plus
`fullName` if available.

### 2.4 Sign in with Google

`POST /v1/auth/google`

Native iOS flow: use the official GoogleSignIn-iOS SDK. After
`GIDSignIn.sharedInstance.signIn(...)`, take
`user.idToken?.tokenString` and POST it.

```json
{ "id_token": "<JWT from Google>" }
```

| Status | Body                                                          | Meaning                                                     |
|--------|---------------------------------------------------------------|-------------------------------------------------------------|
| 200    | `{"token": "...", "user": {"id":"uuid", "email":"..."}}`      | Same semantics as Apple                                     |
| 400    | `{"error":"invalid_payload"}`                                 | Missing id_token                                            |
| 401    | `{"error":"invalid_id_token"}`                                | Google verification failed (sig, exp, aud)                  |
| 409    | `{"error":"account_link_conflict"}`                           | Email already bound to a different sub                      |
| 503    | `{"error":"google_not_configured"}`                           | No `GOOGLE_CLIENT_ID_*` set on the server                   |
| 429    | (rate limited)                                                | 30/15min per IP                                             |

The backend accepts tokens issued for **any** of the configured OAuth
client IDs (`GOOGLE_CLIENT_ID_IOS`, `_ANDROID`, `_WEB`). The iOS app uses
the iOS client ID; the cloud doesn't care which one as long as it's in
the allowlist.

### 2.5 Password reset

Two-step.

`POST /v1/auth/forgot-password`

```json
{ "email": "user@example.com" }
```

Always returns `202 {"ok": true}` regardless of whether the email exists,
to prevent account enumeration. If the email is configured server-side and
the address matches a user, the user receives an email with a link to:

```
${PUBLIC_WEB_URL}/reset?token=<32hex>
```

The link expires after 30 minutes and is single-use.

`POST /v1/auth/reset-password`

```json
{ "token": "<32 hex chars>", "password": "newpw8plus" }
```

| Status | Body                                                  |
|--------|-------------------------------------------------------|
| 200    | `{"ok": true}` — password updated, all sessions revoked |
| 400    | `{"error":"invalid_payload"}` — token format wrong    |
| 410    | `{"error":"token_invalid_or_expired"}`                |

After a successful reset, the user must log in fresh; existing tokens
(including any held in another tab / phone) are revoked.

### 2.6 JWT structure & lifecycle

| Field        | Value                                                              |
|--------------|--------------------------------------------------------------------|
| Algorithm    | HS256                                                              |
| TTL          | 7 days from issuance (`expiresIn: '7d'`)                           |
| Header       | `Authorization: Bearer <jwt>`                                      |
| Claims       | `{ sub: "<user-uuid>", email: "<email>", iat: <unix-seconds>, exp: <unix-seconds> }` |

**Revocation.** Every authenticated request is checked against a per-user
`tokens_valid_after` column. If the token's `iat` predates that timestamp,
the request is rejected with `401 token_revoked`. The column is bumped to
`now()` by:

- Successful password change (`POST /v1/auth/change-password`).
- Explicit "log out everywhere" (`POST /v1/auth/logout-everywhere`).
- Successful password reset (`POST /v1/auth/reset-password`).
- Admin actions: `POST /v1/admin/users/:id/logout-everywhere` and
  soft-delete (`DELETE /v1/admin/users/:id`).

The app should treat `401 token_revoked` (and `401 unauthorized`) as
"sign in again" — clear the keychain entry and route back to the login
screen.

`POST /v1/auth/change-password` (auth required):

```json
{ "current": "currentpw", "next": "newpw8plus" }
```

| Status | Body                          | Notes                                                |
|--------|-------------------------------|------------------------------------------------------|
| 200    | `{"ok": true}`                | Password updated; current token now revoked          |
| 400    | `{"error":"invalid_payload"}` |                                                      |
| 401    | `{"error":"invalid_credentials"}` | Wrong `current`                                  |
| 404    | `{"error":"not_found"}`       | User row missing (rare; treat as "sign in again")    |
| 409    | `{"error":"no_local_password"}` | OAuth-only user (no password to change)            |

`POST /v1/auth/logout-everywhere` (auth required):

```json
{}
```

Returns `200 {"ok": true}` and revokes every JWT for the calling user
(including the one in this request). Useful for a "sign out of all
devices" UI affordance.

There is no separate `POST /v1/auth/logout` on the cloud side — JWTs are
stateless on the wire, so a normal logout simply means the app discards
its locally-stored token.

### 2.7 Get current user

`GET /v1/me` (auth required)

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "created_at": "2026-04-01T10:00:00.000Z",
  "email_verified": true,
  "sub_status": "active",
  "current_period_end": "2026-06-01T10:00:00.000Z"
}
```

`sub_status` is one of `active | trialing | past_due | canceled |
unpaid | incomplete | incomplete_expired | null` (null = never subscribed).
See Section 3.1 for which values grant access.

`current_period_end` is the next renewal date (or, for canceled subs,
the date access will end).

---

## 3. Subscriptions (Stripe)

### 3.1 Check sub status

The `sub_status` field on `GET /v1/me` is canonical. Treat these values as
"sub is active":

```
active
trialing
past_due     # we deliberately keep access during Stripe's 1-3 day card retry
```

Any other value (or null) means inactive — don't allow the user to pair
new devices, and put a "Renew subscription" affordance in the UI.

The list of devices and the ability to control already-paired devices
through the relay does NOT enforce sub status (it just won't return new
pairing codes). Be consistent in the UI: if `sub_status` lapses, show a
soft warning, but don't blow up existing functionality.

### 3.2 Start checkout

`POST /v1/billing/checkout` (auth required)

Body: empty. Response:

```json
{ "url": "https://checkout.stripe.com/c/pay/cs_test_..." }
```

Open the URL in `SFSafariViewController` (preferred — keeps the user in
your app). On success, Stripe redirects to:

```
evolights://billing/success?session_id={CHECKOUT_SESSION_ID}
```

and on cancel to:

```
evolights://billing/cancel
```

The app should:

1. Register the `evolights://` URL scheme in `Info.plist`.
2. On receipt of either callback, dismiss the Safari view and re-fetch
   `GET /v1/me` to update `sub_status`.

> Note: webhook delivery from Stripe to the cloud is asynchronous. After a
> successful checkout the user's `sub_status` may briefly still be the old
> value until the `customer.subscription.created` webhook arrives.
> Recommended: poll `/v1/me` every ~2s for 30s, or show a "checking…"
> spinner that resolves on the first `active` status seen.

| Status | Body                              | Meaning                              |
|--------|-----------------------------------|--------------------------------------|
| 200    | `{"url": "..."}`                  | Open this URL                        |
| 401    | `{"error":"unauthorized"}`        | Bad/expired JWT                      |
| 500    | `{"error":"STRIPE_PRICE_ID_MONTHLY not configured"}` | Server misconfigured |
| 503    | `{"error":"billing_disabled"}`    | Server has no `STRIPE_SECRET_KEY`    |

### 3.3 Manage / cancel an existing subscription

`POST /v1/billing/portal` (auth required)

```json
{ "url": "https://billing.stripe.com/session/..." }
```

Stripe's hosted Customer Portal handles cancel, payment-method update,
invoice history, etc. Same Safari/scheme pattern; return URL is
`evolights://billing/return`.

---

## 4. Device discovery and local control

### 4.1 LAN discovery (Bonjour / mDNS)

Each WLED device publishes a service record at boot:

| Field    | Value                                                  |
|----------|--------------------------------------------------------|
| Type     | `_wled._tcp.`                                          |
| Port     | `80`                                                   |
| Hostname | `<cmDNS>.local` — defaults to `wled-XXXXXX` where XXXXXX is the last 6 hex chars of the MAC; user-renamable via WLED's settings UI |
| TXT      | `mac=<full-mac-no-colons>` (lowercase hex)             |

It also publishes `_http._tcp` on port 80 (vanilla HTTP service record),
so a generic browser can find it too.

iOS Bonjour discovery via `NWBrowser` with `NWBrowser.Descriptor.bonjour(type: "_wled._tcp", domain: nil)`. Resolve each result to get
host + IP; the TXT record's `mac` value is your stable per-device key for
"have I seen this device before" lookups.

Show the discovered list to the user with whatever name comes back from
the device's `/json/info` (`name` field). They tap one to manage it.

### 4.2 First-time device setup (factory new)

When a brand-new (or factory-reset) device boots and has no WiFi
configured:

1. The device starts its own AP with SSID `WLED-AP` (no password by
   default; configurable in source).
2. The user joins the AP. iOS will (usually) prompt with a captive-portal
   sheet; the device serves a setup HTML page at `http://4.3.2.1`.
3. The user enters their home WiFi credentials. The device saves them and
   reboots into station mode.
4. The device joins the home network. Now mDNS picks it up on the LAN.
5. **EvoLights wrinkle:** the very first request to the device after it
   joins the WiFi triggers the EvoLights setup page (see 4.3).

While the device is in AP mode AND no WiFi is configured, the EvoLights
auth gate is relaxed: only the routes needed to complete WiFi setup
(`/`, `/welcome`, `/settings/wifi*`, `*.js`, `*.css`, `/favicon.ico`,
`/settings`, `/settings.js`) bypass auth. Everything else (`/edit`,
`/update`, `/json/cfg`, etc.) is still gated. A LAN attacker on the AP
cannot brick or hijack the device.

### 4.3 Local auth (the EvoLights gate)

#### `GET /auth/status` — public probe

```json
{ "configured": true, "local": true, "cloud": false, "product": "EvoLights" }
```

| Field        | Meaning                                                          |
|--------------|------------------------------------------------------------------|
| `configured` | A local admin account exists on the device                       |
| `local`      | Local auth is enabled (master switch, currently always `true`)  |
| `cloud`      | The device is paired to the cloud and currently online via MQTT  |
| `product`    | Always `"EvoLights"` — use this to distinguish from vanilla WLED |

Use this on first contact: `cloud=true` means "this device can be
controlled via the cloud relay too", `configured=false` means "send the
user to the setup screen".

#### `POST /auth/setup` — first-time admin creation

Only valid when `configured == false`.

```json
{ "username": "admin", "password": "min8chars" }
```

Constraints (enforced server-side):

- `username` length ≥ 3, ≤ 32
- `password` length ≥ 8, ≤ 64
- Single-flight: a second concurrent request gets `409`.
- **Physical-presence proxy:** if the device has been online longer than 5
  minutes AND is NOT in AP mode, the request is refused with `403
  physical presence required`. The user must power-cycle the device first.

| Status | Body                                                                      |
|--------|---------------------------------------------------------------------------|
| 200    | `{"token": "32-hex-chars"}` plus `Set-Cookie: EVOAUTH=...`                |
| 400    | `username >=3 chars, password >=8 chars`                                  |
| 403    | `physical presence required: power-cycle the device before running setup` |
| 409    | `already configured or setup in progress`                                 |
| 500    | `failed to store credentials`                                             |

The app receives a session token and the device sets `EVOAUTH` as an
HttpOnly cookie. Either is enough for subsequent calls.

#### `POST /auth/login`

```json
{ "username": "admin", "password": "..." }
```

| Status | Body                                              |
|--------|---------------------------------------------------|
| 200    | `{"token": "32-hex-chars"}` + `Set-Cookie EVOAUTH=...` |
| 401    | `{"error":"invalid_credentials"}`                 |

The server runs PBKDF2-SHA256 (~600ms on ESP32) on every login attempt,
including unknown-username attempts, to deny a timing oracle.

#### `POST /auth/logout`

Auth required. Body: empty. Returns `200 {"ok":true}` and clears the
cookie. Idempotent.

#### Session model

- 7-day TTL.
- **In-RAM only.** A device reboot wipes all sessions; users must log in
  again. This is intentional: sessions are not worth persisting through
  a reboot, and writing them to flash would burn cycles.
- Up to 8 concurrent sessions per device. The 9th login evicts the
  least-recently-used slot.
- The token is a 32-character hex string (16 random bytes).

#### Three ways to send the token

| Header / cookie                            | When to use                          |
|--------------------------------------------|--------------------------------------|
| `Authorization: Bearer <token>`            | Standard for native HTTP clients     |
| `X-EvoLights-Token: <token>`               | Where Authorization header is awkward |
| `Cookie: EVOAUTH=<token>`                  | Browser sessions (set by /auth/login)|

> The cookie parse is anchored: only `EVOAUTH=` at start-of-cookie or
> immediately after `; ` is accepted. Don't accidentally collide names
> with `EVOAUTHX=…`.

### 4.4 WLED JSON API

Once authed, the entire WLED JSON API at `/json/*` is reachable. The
canonical reference is the WLED documentation at
https://kno.wled.ge/interfaces/json-api/ — **don't** re-implement that
spec from scratch in the iOS app; treat the WLED docs as authoritative
and use this section as a quick-reference for the most common calls.

| Endpoint               | Method | Purpose                                            |
|------------------------|--------|----------------------------------------------------|
| `GET /json`            | GET    | Full state + info + effects + palettes (one shot)  |
| `GET /json/state`      | GET    | Current `state` object only                        |
| `POST /json/state`     | POST   | Set state (color, brightness, effect, segments)    |
| `GET /json/info`       | GET    | Device info: name, version, mac, free heap, leds   |
| `GET /json/effects`    | GET    | Array of effect names                              |
| `GET /json/palettes`   | GET    | Array of palette names                             |
| `GET /json/cfg`        | GET    | Full config (auth required)                        |
| `POST /json/cfg`       | POST   | Update config (auth required)                      |

Quick examples (omitting auth header for brevity):

Set brightness to half + turn on:
```http
POST /json/state
{ "on": true, "bri": 128 }
```

Set first segment to solid red:
```http
POST /json/state
{ "seg": [{ "id": 0, "col": [[255,0,0]], "fx": 0 }] }
```

Pick effect 22 (palette-mapped):
```http
POST /json/state
{ "seg": [{ "id": 0, "fx": 22, "sx": 128, "ix": 128 }] }
```

The `seg.col` array carries up to three colours per segment; `fx` /
`sx` / `ix` / `pal` are effect / speed / intensity / palette indices.
Pull the actual indices off `/json/effects` and `/json/palettes` so the
UI can render labels.

### 4.5 WebSockets — live state

`ws://<device>/ws`

WLED pushes the full `state` object every time it changes (button press,
JSON API update from any client, scheduled preset, etc.). The frame format
is JSON, identical to the `state` portion of `GET /json`. Use this in
preference to polling for any "current colour / brightness / effect" UI
that needs to stay live.

Auth model on the WebSocket: the WebSocket upgrade goes through the same
EvoAuth gate. Pass the cookie in the upgrade request, or attach the
token via query string only as a fallback (cookies are preferred and
simpler from `URLSessionWebSocketTask`).

---

## 5. Cloud relay control

When the phone is not on the same LAN as the device, control flows
through the cloud panel.

### 5.1 Pair a device to the user's cloud account

This is a three-party dance: the app, the cloud, and the device.

**Step 1 — App requests a code from the cloud.**

`POST /v1/pairing/codes` (auth required, **active sub required**)

Body: empty. Response:

```json
{
  "code": "ABC234",
  "expires_in": 300,
  "cloud_api": "https://api.evolights.io"
}
```

| Status | Body                                  | Meaning                          |
|--------|---------------------------------------|----------------------------------|
| 200    | as above                              | Code issued                      |
| 401    | `{"error":"unauthorized"}`            | No / bad JWT                     |
| 402    | `{"error":"subscription_required"}`   | Sub status not in active set     |

The code is a 6-character base32 (Crockford-ish: no `0/1/I/O` confusion),
single-use, and TTL is 5 minutes by default.

**Step 2 — User pastes the code into the device.**

The app must already be authenticated locally to the device. The device
exposes `POST /cloud/pair` (registered by the `cloud_relay` usermod):

```http
POST /cloud/pair
Authorization: Bearer <local-evoauth-token>
Content-Type: application/json

{ "code": "ABC234", "cloud_api": "https://api.evolights.io" }
```

The device internally calls `POST /v1/devices/redeem` on the cloud (with
its `chip_id` derived from the ESP32's eFuse MAC), receives MQTT
credentials, persists them to `wsec.json`, and connects to the broker.

| Device returns | Body                                                              |
|----------------|-------------------------------------------------------------------|
| 200            | `{"ok": true, "device_id": "uuid"}`                               |
| 400            | `{"error":"missing code or cloud_api"}`                           |
| 4xx/5xx        | Whatever the cloud's `/v1/devices/redeem` returned, passed through |
| 502            | `{"error":"cloud unreachable"}` or `{"error":"invalid cloud response"}` |

Cloud error codes returned through the device:

| Status | Body                                                          |
|--------|---------------------------------------------------------------|
| 410    | `{"error":"code_expired_or_used"}`                            |
| 402    | `{"error":"subscription_inactive"}`                           |
| 409    | `{"error":"device_already_paired_to_another_account"}`        |
| 500    | `{"error":"broker_provision_failed"}` or `{"error":"redeem_failed"}` |

`/cloud/pair` requires a real local session token — the cloud-trusted
loopback token does NOT satisfy it. This prevents a remote actor with
the relay token from re-pairing the device.

**Step 3 — App polls / refreshes its device list.**

`GET /v1/devices` will show the newly paired device (see 5.3). The
device's first MQTT message is an `online` announcement on
`evolights/<device_id>/state`.

#### Re-pair semantics

If a device is already paired and the same user asks for a new code and
re-pairs (e.g. reset the credentials on the device side), the cloud
detects the existing `chip_id`, **rotates** the MQTT creds, and updates
the same `device_id` row. If a DIFFERENT user tries to pair the same
hardware, the cloud refuses with `409
device_already_paired_to_another_account` — the original owner has to
unpair first via `DELETE /v1/devices/:id` (Section 5.3).

### 5.2 Send a command via the cloud relay

`POST /v1/devices/:id/relay` (auth required, ownership required)

```json
{
  "path":   "/json/state",
  "method": "POST",
  "body":   { "on": true, "bri": 128 }
}
```

The cloud publishes `{id, path, method, body}` on
`evolights/<device_id>/cmd`, the device picks it up over MQTT, dispatches
the request into its own local HTTP stack via loopback (using the
cloud-trusted token to bypass local auth), and publishes the response on
`evolights/<device_id>/state` keyed by the same `id`.

| Status | Body                                                  | Meaning                              |
|--------|-------------------------------------------------------|--------------------------------------|
| 2xx    | (whatever the device returned for that path)          | Success — `status` taken from device |
| 400    | `{"error":"invalid_payload"}`                         | Schema invalid                       |
| 401    | `{"error":"unauthorized"}`                            | Bad JWT                              |
| 404    | `{"error":"device_not_found"}`                        | Not yours, or ID wrong               |
| 502    | `{"error":"relay_failed", "detail":"..."}`            | Transport error                      |
| 504    | `{"error":"device_timeout"}`                          | Device didn't ack within 5s          |

Cross-device leak guard: even though a malicious paired device could
publish state with any `id`, the cloud verifies that the publishing
device's own ID matches the device the request was addressed to before
delivering the reply. Don't worry about it from the app side.

`method` is one of `GET | POST | PUT | DELETE`, default `GET` if omitted.
`body` is optional.

**Mental model:** this endpoint is a thin pass-through. The same JSON
that you'd POST to `/json/state` directly on the LAN is what you put in
the `body` field. Build your "send a command" function once with a
`transport` parameter that picks LAN-direct or cloud-relay, and the
payload shape is identical either way.

### 5.3 List, rename, delete devices

`GET /v1/devices` (auth required)

```json
{
  "devices": [
    {
      "id":               "uuid",
      "name":             "EvoLights AB12",
      "hardware_id":      "abcd1234",
      "firmware_version": "0.1.0+ev3",
      "last_seen_at":     "2026-05-01T12:34:56.000Z",
      "created_at":       "2026-04-01T10:00:00.000Z"
    }
  ]
}
```

`last_seen_at` is touched on every successful relay round-trip (Section
5.2). If it's stale by more than ~30s, the device is probably offline —
fall back to the LAN path or surface a "device offline" indicator.

`PATCH /v1/devices/:id`

```json
{ "name": "Living room" }
```

| Status | Body                         |
|--------|------------------------------|
| 200    | `{"id":"uuid","name":"..."}` |
| 400    | `{"error":"invalid_payload"}` (name 1-64 chars) |
| 404    | `{"error":"not_found"}`      |

`DELETE /v1/devices/:id`

```json
{}
```

Returns `200 {"ok": true}`. This unpairs the device: the cloud revokes
its MQTT credentials and removes its ACL entry. The device itself doesn't
know it's been unpaired until its next reconnect attempt — until then it
keeps trying to reach the broker with creds that no longer work. The user
should be told to either:

- Power-cycle the device (it'll fail to reconnect, eventually wedge in
  local-only mode), or
- Visit the device on the LAN and `POST /cloud/unpair` to clear its
  `wsec.json` state explicitly.

### 5.4 Local fall-through and the TLS gap

The device will keep working over LAN (mDNS + local auth) regardless of
cloud state. If the cloud is unreachable but the phone is on the same
network, control still works.

> **TLS gap** — the firmware-side MQTT client currently connects to the
> broker with **plain TCP** (`WiFiClient`, not `WiFiClientSecure`). This
> is documented and tracked in `firmware/usermods/cloud_relay/cloud_relay.cpp`.
> Until that's fixed, MQTT auth credentials traverse plaintext from
> device → broker. Operator mitigations are documented in DEPLOYMENT.md
> Section 4. **App impact: zero** — the app talks to the cloud over HTTPS
> regardless. Just be aware so you don't claim "end-to-end encrypted" in
> marketing copy until the firmware is updated.

---

## 6. OTA firmware updates

### 6.1 Push the latest firmware to a single device

`POST /v1/devices/:id/ota/push` (auth required, ownership required)

Optional body — both fields default if omitted:

```json
{ "board": "esp32dev_evolights", "channel": "stable" }
```

`channel` is one of `stable | beta | dev`.

| Status | Body                                       | Meaning                                          |
|--------|--------------------------------------------|--------------------------------------------------|
| 200    | `{"ok": true, "pushed": "0.1.0+ev3"}`      | Manifest published to device's /ota topic         |
| 401    | `{"error":"unauthorized"}`                 |                                                  |
| 404    | `{"error":"device_not_found"}`             | Not yours / wrong ID                             |
| 404    | `{"error":"no_firmware"}`                  | No firmware row for that (board, channel)        |

The cloud publishes a JSON manifest on `evolights/<device_id>/ota`:

```json
{ "version": "0.1.0+ev3", "url": "https://...bin", "sig": "<base64 ed25519 sig over `version|url|sha256`>" }
```

The device verifies the signature against its compiled-in Ed25519 public
key, downloads the binary (HTTP — sig is the trust anchor, not TLS),
re-hashes, compares against `sha256` declared in the manifest, flashes,
and reboots.

> ⚠ **Firmware-side OTA verifier status.** The signed-OTA verification
> code referenced in the original outline (`usermods/cloud_relay/ota_verifier.cpp`)
> is **not present** in this branch. The cloud already signs and
> publishes manifests; the device-side handler that subscribes to
> `evolights/<id>/ota`, verifies the signature, downloads, hashes, and
> applies is on a separate branch (`feat/firmware-signed-ota`) and
> hasn't landed on `evolights/main` yet. Until that lands, pushing OTA
> from the app will publish a manifest the device receives but does
> nothing with. The cloud-side endpoints work today; treat the device-side
> behaviour as "wired but not yet active" until the verifier lands.

### 6.2 What the user sees during an update

(Once the verifier lands on the device.)

1. App calls `POST /v1/devices/:id/ota/push`. Returns immediately with
   the version it asked the device to install.
2. The device acknowledges by going offline mid-flash; `last_seen_at`
   stops advancing.
3. ~30-90 seconds later, the device reconnects with the new
   `firmware_version`.
4. The app polls `GET /v1/devices/:id` (or refreshes the list) to detect
   the new version.

Recommended UX: show a progress affordance and poll once every 5
seconds for up to 3 minutes. If `firmware_version` doesn't change, mark
the update as failed (no automatic recovery — user can retry, and the
old firmware is still flashed since OTA only flashes the inactive
partition).

### 6.3 Trust model

- **Signature is the trust anchor.** Plain HTTP for the binary download
  is fine because the device verifies the Ed25519 signature on
  `version|url|sha256` against its compiled-in public key before
  flashing.
- **Downgrade protection.** The device refuses to apply a manifest with
  a `version` not strictly greater than the currently-running version
  (per the planned `feat/firmware-signed-ota` branch). Today's `VERSION`
  in `wled00/wled.h` is an integer (`2605011`); the version comparison
  is integer-greater-than.
- **No fall-back.** A failed signature verification does not retry, does
  not "ask again later" — it logs and drops. The cloud cannot push
  unsigned or wrongly-signed firmware to a device shipping with the
  matching public key, even if the cloud panel itself is compromised.

---

## 7. Admin endpoints

These are present on the cloud panel but the mobile app likely doesn't
need to expose them. They're documented here so the iOS agent knows what
exists. Build them only if explicitly asked.

All `/v1/admin/*` routes require both `requireUser` (valid JWT, account
exists, token not revoked) AND `requireAdmin` (`users.is_admin = true`).
Bootstrap admin access via the `npm run admin:promote -- email@x` CLI
on the server (see DEPLOYMENT.md Section 11). There is **no** self-promote
endpoint.

| Method | Path                                          | Purpose                                       |
|--------|-----------------------------------------------|-----------------------------------------------|
| GET    | `/v1/admin/stats`                             | Counts (users, devices, active subs, MRR estimate) |
| GET    | `/v1/admin/users?q=&limit=&offset=`           | Search/list users (substring on email)        |
| GET    | `/v1/admin/users/:id`                         | User detail (incl. devices, sub, providers)   |
| POST   | `/v1/admin/users/:id/promote`                 | Set `is_admin = true`                         |
| POST   | `/v1/admin/users/:id/demote`                  | Set `is_admin = false` (refuses self-demote) |
| POST   | `/v1/admin/users/:id/logout-everywhere`       | Bump `tokens_valid_after`                     |
| DELETE | `/v1/admin/users/:id`                         | Soft-delete (refuses self-delete)             |
| GET    | `/v1/admin/stripe/products`                   | List Stripe products                          |
| POST   | `/v1/admin/stripe/products`                   | Create product `{name, description?, active?}` |
| PATCH  | `/v1/admin/stripe/products/:id`               | Update product                                |
| GET    | `/v1/admin/stripe/prices?product_id=`         | List prices                                   |
| POST   | `/v1/admin/stripe/prices`                     | Create price `{product_id, currency, unit_amount, recurring_interval}` |
| GET    | `/v1/admin/stripe/coupons`                    | List coupons                                  |
| POST   | `/v1/admin/stripe/coupons`                    | Create coupon (see source for body shape)    |

For Stripe operations the operator will probably go to the Stripe
dashboard directly; these endpoints exist mostly for headless / scripted
provisioning.

A `403 admin_required` is returned when a non-admin JWT hits any of these.

---

## 8. Errors

All error responses share the envelope `{"error": "snake_case_code",
"details"?: any}`. The most common codes the app will see, with cause
and suggested handling:

| Code                                       | Status | When                                   | App behaviour                                |
|--------------------------------------------|--------|----------------------------------------|----------------------------------------------|
| `invalid_payload`                          | 400    | Schema validation failed               | Show "please check the form"; surface `details` for dev builds |
| `invalid_credentials`                      | 401    | Wrong email/password or wrong device pw| "Invalid credentials"                        |
| `unauthorized`                             | 401    | No JWT, expired JWT, deleted user      | Sign user out and route to login             |
| `token_revoked`                            | 401    | JWT predates `tokens_valid_after`      | Same — sign out + login                      |
| `admin_required`                           | 403    | Non-admin hit `/v1/admin/*`            | Hide the admin UI from this user             |
| `subscription_required`                    | 402    | Tried to issue pairing code w/o active sub | "Subscribe to add devices"               |
| `subscription_inactive`                    | 402    | Sub lapsed during pairing window       | Same                                         |
| `code_expired_or_used`                     | 410    | Pairing code stale                     | "Issue a new code"                           |
| `device_already_paired_to_another_account` | 409    | Hardware already owned by someone else | Tell user to ask the previous owner to unpair |
| `device_not_found`                         | 404    | ID wrong or not the user's device      | Refresh `/v1/devices`                        |
| `device_timeout`                           | 504    | Relay didn't get a reply in 5s         | Show "device offline"; offer LAN fallback    |
| `relay_failed`                             | 502    | MQTT/transport error                   | Retry with backoff                           |
| `no_firmware`                              | 404    | OTA push but no manifest registered    | Show "no update available"                   |
| `billing_disabled`                         | 503    | Server has no Stripe key               | Show "billing temporarily unavailable"       |
| `signing_unavailable`                      | 503    | Server has no OTA signing key          | Affects only `/v1/ota/firmwares` (admin)     |
| `apple_not_configured`                     | 503    | No `APPLE_CLIENT_ID` on server         | Hide Apple sign-in button                    |
| `google_not_configured`                    | 503    | No Google client ID on server          | Hide Google sign-in button                   |
| `account_link_conflict`                    | 409    | OAuth email matches account with diff sub | "Sign in with the original method"        |
| `bad_signature`                            | 400    | Stripe webhook only — irrelevant to app|                                              |
| `email_in_use`                             | 409    | Register with existing email           | "Try logging in"                             |
| `cannot_demote_self`                       | 409    | Admin trying to self-demote            | UI shouldn't allow this                      |
| `cannot_delete_self`                       | 409    | Admin trying to self-delete            | UI shouldn't allow this                      |
| `not_found`                                | 404    | Generic "row not present"              |                                              |

Rate limiting: `429 Too Many Requests` with a `Retry-After` header (seconds).
Honour it; don't retry-loop into the wall.

5xx: assume transient; exponential backoff from 1s up to 30s, with
jitter.

---

## 9. iOS-specific notes

### 9.1 Keychain

Store these in `kSecClassGenericPassword` items, accessible only when
unlocked (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`):

| Account              | Service            | Value                                |
|----------------------|--------------------|--------------------------------------|
| `cloud-jwt`          | `io.evolights.app` | The cloud JWT                        |
| `device-<uuid>-token`| `io.evolights.app` | Per-device local-auth token          |

Wipe on logout / "logout everywhere".

### 9.2 ATS (App Transport Security)

The cloud is HTTPS so default ATS works. For local device control, you're
talking to a private-IP device over plain HTTP. Add an exception:

```xml
<!-- Info.plist -->
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsLocalNetworking</key>
  <true/>
</dict>
```

`NSAllowsLocalNetworking` permits HTTP to RFC 1918 / link-local
addresses without disabling ATS for the rest of the app.

iOS 14+: also add the `NSLocalNetworkUsageDescription` string to
`Info.plist` and (for Bonjour discovery) `NSBonjourServices` listing
`_wled._tcp` — otherwise `NWBrowser` will silently return nothing.

```xml
<key>NSLocalNetworkUsageDescription</key>
<string>EvoLights discovers and controls smart lights on your local network.</string>

<key>NSBonjourServices</key>
<array>
  <string>_wled._tcp</string>
</array>
```

### 9.3 URL schemes

Register `evolights://` as a CFBundleURLType in `Info.plist`. Handle
these paths in your `App.onOpenURL`:

| URL                                                     | Action                                 |
|---------------------------------------------------------|----------------------------------------|
| `evolights://billing/success?session_id=...`            | Dismiss SafariViewController; refresh `/v1/me` |
| `evolights://billing/cancel`                            | Dismiss SafariViewController           |
| `evolights://billing/return`                            | Dismiss SafariViewController; refresh `/v1/me` |

### 9.4 Sign in with Apple

- Add the "Sign in with Apple" capability in Xcode (Signing &
  Capabilities). This provisions an entitlement and registers your bundle
  ID with Apple as an Apple-ID-using service.
- The cloud's `APPLE_CLIENT_ID` must equal the audience claim Apple puts
  in the id_token. For native iOS that's normally the bundle ID. For
  web/Android-shared deployments, Apple uses a separately-registered
  "Services ID". Coordinate with the operator: you tell them your bundle
  ID; they set `APPLE_CLIENT_ID` to match.

### 9.5 Sign in with Google

Use the official `GoogleSignIn-iOS` SDK (SwiftPM). After
`GIDSignIn.sharedInstance.signIn(withPresenting:)`, take
`result.user.idToken?.tokenString` and POST to `/v1/auth/google`.

The server-side `GOOGLE_CLIENT_ID_IOS` must equal the iOS OAuth client ID
you create in Google Cloud Console.

### 9.6 Bonjour / `NWBrowser` snippet

```swift
let browser = NWBrowser(
  for: .bonjourWithTXTRecord(type: "_wled._tcp", domain: nil),
  using: .tcp
)
browser.browseResultsChangedHandler = { results, _ in
  for result in results {
    if case let .service(name, type, domain, _) = result.endpoint {
      // Resolve via NWConnection using the result.endpoint to get host+port,
      // or use Network.framework's NWEndpoint helper.
    }
  }
}
browser.start(queue: .main)
```

### 9.7 Background mode (future)

Push notifications when devices come online / fail OTA / etc. is **not
implemented** server-side yet. Plan an APNs path in the architecture
(`UNUserNotificationCenter` permission flow at first device pairing) but
don't promise it in v1.

### 9.8 Settings.bundle for environment switching

Ship a `Settings.bundle` with at minimum:

| Key             | Default                       | Notes                                     |
|-----------------|-------------------------------|-------------------------------------------|
| `cloud_api_url` | `https://api.evolights.io`    | Read at startup; can be staging URL       |
| `log_level`     | `info`                        | `debug` for QA builds                     |

Read with `UserDefaults.standard.string(forKey:)`. The cloud panel does
not return its own URL anywhere, so this must be a client-side setting.

### 9.9 Keep the request shape symmetric across transports

Build one `func sendCommand(deviceID, path, method, body)` function that
chooses transport based on whether the LAN endpoint is reachable. Both
LAN-direct (`POST /json/state`) and cloud-relay (`POST /v1/devices/:id/relay`
with `body: {path, method, body}`) wrap the same payload. The user
shouldn't see different latency or behaviour as they walk out of
their house.

---

## Appendix A — End-to-end first-run flow (for testing)

A scripted user journey the QA test plan can follow:

1. Install app fresh. Tap "Sign up" → create cloud account →
   `POST /v1/auth/register` returns 201 with JWT.
2. Tap "Subscribe" → `POST /v1/billing/checkout` → SafariViewController →
   complete test card `4242 4242 4242 4242` → returns to
   `evolights://billing/success` → poll `GET /v1/me` → `sub_status` flips
   to `active` within ~5s.
3. Power up a fresh EvoLights device. Phone joins device's `WLED-AP`.
4. Captive portal opens → enter home WiFi → device reboots.
5. Phone leaves AP, rejoins home WiFi. App auto-discovers via Bonjour.
6. App probes `GET /auth/status` → `configured: false` → opens setup
   screen → user creates `admin` / 8+-char password →
   `POST /auth/setup` returns token.
7. App displays "pair to cloud" affordance → calls
   `POST /v1/pairing/codes` → shows the 6-char code.
8. App calls `POST /cloud/pair` on the device with code + cloud_api URL.
   Device redeems, gets MQTT creds, persists, connects.
9. App refreshes `GET /v1/devices` → device appears.
10. User leaves the WiFi network. App calls
    `POST /v1/devices/:id/relay { path:"/json/state", method:"POST", body:{on:false} }`
    from cellular → device turns off.
11. User returns home. App detects LAN device again. Same control commands
    now go LAN-direct for lower latency.

---

## Appendix B — Useful curl recipes

```bash
# Register
curl -X POST https://api.evolights.io/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"hunter22extra"}'

# Login → token
JWT=$(curl -s -X POST https://api.evolights.io/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"hunter22extra"}' | jq -r .token)

# Whoami
curl https://api.evolights.io/v1/me -H "Authorization: Bearer $JWT"

# Issue pairing code
curl -X POST https://api.evolights.io/v1/pairing/codes -H "Authorization: Bearer $JWT"

# List devices
curl https://api.evolights.io/v1/devices -H "Authorization: Bearer $JWT"

# Send a state update via relay
curl -X POST https://api.evolights.io/v1/devices/<device-uuid>/relay \
  -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"path":"/json/state","method":"POST","body":{"on":true,"bri":200}}'

# Direct LAN call (after local login on the device)
DEV_TOKEN=$(curl -s -X POST http://wled-ab12.local/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"hunter22extra"}' | jq -r .token)
curl http://wled-ab12.local/json/state \
  -H "Authorization: Bearer $DEV_TOKEN"
```
