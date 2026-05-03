# EvoLights Cloud Deployment Guide

> Operator runbook. From a fresh server to production-serving in under an
> hour. Written for someone who can run `docker compose` but isn't a
> systems programmer.
>
> The document walks top-to-bottom. If something fails, the troubleshooting
> notes for that step are inline — don't skip ahead.

---

## 1. What you need before you start

A virtual machine or bare-metal box with:

- **OS**: Linux (any modern distro — Ubuntu 22.04 / 24.04, Debian 12,
  Rocky 9 all tested in spirit). The instructions here use Debian/Ubuntu
  syntax for `apt`; substitute `dnf` on RHEL-likes.
- **CPU/RAM**: 2 vCPU, 2 GB RAM minimum. The api process is
  Node.js + Fastify and idles at ~80 MB; Postgres 16 idles at ~80 MB;
  Mosquitto idles at ~10 MB.
- **Disk**: 20 GB. Most of it is Docker images and the Postgres data
  volume. Plan for ~5 MB per user account in the long term (counting
  pairing codes and password reset tokens that haven't been pruned).
- **Software**: Docker Engine 24+ and the `docker compose` plugin.
  ```bash
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker $USER  # log out and back in
  ```
- **Network**: A public IPv4 address. The cloud panel needs to be
  reachable from anywhere the user's mobile app runs (i.e. the public
  internet) and the user's devices need to reach the broker (also public
  internet).

You also need:

- **A domain name** with DNS you control. Pick two subdomains:
  - `api.evolights.io` (or whatever you choose) → A record to your
    server's public IP. Used for the cloud REST API.
  - `mqtt.evolights.io` → A record to the same IP. Used by devices for
    the MQTT broker.
  Strictly speaking you can use one hostname, but separating them lets
  you put the API behind a CDN later without breaking devices.
- **A Stripe account** (https://dashboard.stripe.com). Start in test
  mode; switch to live mode only after the test flow works end-to-end.
- (Optional) **An Apple Developer account** if you want Sign in with
  Apple (~$99/yr).
- (Optional) **A Google Cloud account** for Sign in with Google (free
  tier is plenty).
- (Optional) **An email provider** for password resets and future
  transactional email. Two paths supported:
  - SMTP — works with SendGrid, AWS SES, Mailgun, Postmark, Gmail
    App Passwords, or your own server.
  - Microsoft Graph — for organizations already using Microsoft 365.

---

## 2. Get the code

```bash
git clone https://github.com/johnsonflix/evolights-cloud.git
cd evolights-cloud
cp .env.example .env
```

Open `.env` in your editor. Every setting below maps to a line in this
file. Keep `.env` out of version control (`.gitignore` already excludes
it; do not commit it under any circumstance).

The repo layout:

```
evolights-cloud/
├── api/                         # Fastify + Postgres + MQTT publisher
│   ├── Dockerfile
│   └── src/
├── docker-compose.yml           # The full stack: api + postgres + mosquitto
├── mosquitto/
│   ├── mosquitto.conf
│   ├── acl                      # rewritten by the api at pairing time
│   └── certs/                   # you will populate this with TLS certs
├── secrets/                     # YOU create this; .gitignored
│   └── ota-prod.key             # generated below
├── tools/
│   └── generate-ota-keys.sh
└── .env.example
```

---

## 3. Generate secrets

### 3.1 `JWT_SECRET`

Used to sign user JWTs. **Must** be at least 32 chars; the API refuses to
boot otherwise. Use 64 chars of randomness so a future move to a
larger-key algorithm doesn't require regenerating accounts.

```bash
openssl rand -hex 64
```

Paste into `.env`:

```
JWT_SECRET=<paste the 128-character hex string here>
```

If you ever rotate this value, **every existing user is logged out**
(every issued JWT becomes unverifiable). Plan accordingly.

### 3.2 `POSTGRES_PASSWORD`

```bash
openssl rand -base64 32 | tr -d '/+=' | head -c 32
```

Paste in two places:

```
POSTGRES_PASSWORD=<paste here>
DATABASE_URL=postgres://evolights:<same password here>@postgres:5432/evolights
```

The `evolights` username is the default `POSTGRES_USER`; if you change
that, change both halves of `DATABASE_URL` too.

### 3.3 `MQTT_API_PASSWORD`

The cloud API uses this to authenticate to Mosquitto as the privileged
`api` user (full read/write across `evolights/#`).

```bash
openssl rand -base64 32 | tr -d '/+=' | head -c 32
```

Paste:

```
MQTT_API_USERNAME=api
MQTT_API_PASSWORD=<paste here>
```

You also need to register this user with Mosquitto:

```bash
# This is run AGAINST a NOT-YET-RUNNING mosquitto config. Easiest is to
# bring up just the broker briefly, set the password, bring it down.
docker compose up -d mosquitto
docker compose exec mosquitto \
  mosquitto_passwd -b /mosquitto/config/passwd api '<the same password>'
docker compose down
```

(Re-run the `mosquitto_passwd` command if you rotate the password
later. The `acl` file already contains a `user api` block granting
`evolights/#` access — leave that alone.)

### 3.4 OTA signing keypair

This is the most important secret in the whole system. The Ed25519
**private key** lives only on the cloud panel and signs every firmware
manifest the cloud distributes. The **public key** is compiled into
firmware and trusted forever by every device that ships with that build.

If the private key leaks: every device shipping with the matching public
key will trust whatever firmware that key signs. Plan its custody as you
would a code-signing certificate — store an offline backup (USB key in
a safe), and consider a hardware token / HSM down the line.

Generate it now:

```bash
mkdir -p secrets
bash tools/generate-ota-keys.sh secrets/ota-prod
```

This produces three files:

| File                    | Goes where                                           |
|-------------------------|------------------------------------------------------|
| `secrets/ota-prod.key`  | Mounted into the api container at `OTA_SIGNING_KEY_PATH`. **Never** commit. |
| `secrets/ota-prod.pub`  | Human-readable PEM. Keep alongside the key.          |
| `secrets/ota-prod.b64`  | Raw 32-byte pubkey, base64. **This** goes into the firmware (Section 9). |

Set in `.env`:

```
OTA_SIGNING_KEY_PATH=/run/secrets/ota-signing.key
```

Mount it in `docker-compose.yml` (already wired in `.env.example`'s
expected layout — add this volume to the `api` service if not already
present):

```yaml
  api:
    # ...existing config...
    volumes:
      - ./secrets/ota-prod.key:/run/secrets/ota-signing.key:ro
```

Verify the key is readable inside the container before going further:

```bash
docker compose run --rm api ls -la /run/secrets/ota-signing.key
```

Make a backup of `secrets/ota-prod.key` to an air-gapped medium **now**.
Without it you cannot sign new firmware updates; existing deployed
devices keep working but become unupdatable.

---

## 4. TLS for the MQTT broker

The broker accepts traffic on port 8883 (TLS) on the public internet.
You need a real, browser-trusted certificate for `mqtt.evolights.io`.

### 4.1 Get a certificate (Let's Encrypt)

The simplest path is `certbot --standalone` on the server. **Briefly**
free up port 80 (or use `--http-01` with a different challenge):

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d mqtt.evolights.io \
  --agree-tos -m you@evolights.io --no-eff-email
```

This produces `/etc/letsencrypt/live/mqtt.evolights.io/{fullchain,privkey}.pem`.

### 4.2 Mount the certs into Mosquitto

Copy or symlink them into the repo's `mosquitto/certs/` directory (the
docker-compose mount is already set up to expect this path):

```bash
sudo mkdir -p mosquitto/certs
sudo cp /etc/letsencrypt/live/mqtt.evolights.io/fullchain.pem mosquitto/certs/
sudo cp /etc/letsencrypt/live/mqtt.evolights.io/privkey.pem  mosquitto/certs/
sudo chown -R 1883:1883 mosquitto/certs   # mosquitto runs as uid 1883
sudo chmod 600 mosquitto/certs/privkey.pem
```

### 4.3 Enable the TLS listener

Open `mosquitto/mosquitto.conf` and uncomment the TLS listener block:

```
listener 8883
protocol mqtt
cafile   /mosquitto/certs/fullchain.pem
certfile /mosquitto/certs/fullchain.pem
keyfile  /mosquitto/certs/privkey.pem
require_certificate false
tls_version tlsv1.2
```

Restart the broker:

```bash
docker compose restart mosquitto
docker compose logs --tail 50 mosquitto
```

You should see `Opening ipv4 listen socket on port 8883.` with no errors.

### 4.4 Renewal

Let's Encrypt certs expire every 90 days. Add a renewal hook (the
broker reloads on SIGHUP, no downtime):

```bash
sudo crontab -e
# Add:
0 3 * * 0 certbot renew --quiet --deploy-hook 'cp /etc/letsencrypt/live/mqtt.evolights.io/* /path/to/evolights-cloud/mosquitto/certs/ && docker kill -s HUP evolights-cloud-mosquitto-1'
```

### 4.5 ⚠ Known gap — firmware-side TLS not yet implemented

The current firmware connects to the broker over **plain TCP** (the
`cloud_relay` usermod uses `WiFiClient`, not `WiFiClientSecure`). This
is documented in the source as a known limitation and is tracked on a
separate firmware branch. Until that fix ships:

The broker exposes both a plain TCP listener on `1883` and the TLS
listener you just configured on `8883`. Devices today connect to
`1883`. Their MQTT username and password traverse the wire in the clear.

Pick **one** mitigation for production:

| Option                                            | Pros                                  | Cons                                  |
|---------------------------------------------------|---------------------------------------|---------------------------------------|
| (a) Bind 1883 to localhost only, run **stunnel**  | Devices connect to 8883 over TLS via stunnel sidecar; transparent to them. | Extra moving part on every device side. |
| (b) Put devices on a **WireGuard / Tailscale** mesh that reaches the broker | Real end-to-end encryption today.    | Each device needs the VPN client (heavy on ESP32). |
| (c) **IP-allowlist** the broker on the firewall   | Cheapest; works for a known-IP user base. | Doesn't scale to a public product.    |
| (d) Wait for the firmware fix before you ship.    | Correct.                              | Delays launch.                        |

Most operators ship (c) for the alpha cohort and migrate to firmware-side
TLS as soon as the patch lands. Document your choice somewhere durable.

To bind 1883 to localhost-only on the broker (option a / d):

```yaml
# docker-compose.yml
  mosquitto:
    ports:
      - "127.0.0.1:1883:1883"
      - "8883:8883"
```

---

## 5. Configure Stripe

### 5.1 Test mode first

You will swap to live keys later. Doing this in test mode first lets you
verify the entire subscription flow without spending real money.

1. Go to https://dashboard.stripe.com → make sure the toggle in the top
   left is on "Test mode".
2. Developers → API keys → reveal the **Secret key** (`sk_test_...`).
   Paste into `.env`:
   ```
   STRIPE_SECRET_KEY=sk_test_...
   ```
3. Products → Add product:
   - Name: "EvoLights Cloud Monthly" (or whatever you want)
   - Pricing: Recurring, $9.99 / month (or your number).
   - Save. Copy the price ID (`price_...`) shown on the product page.
   - Paste into `.env`:
     ```
     STRIPE_PRICE_ID_MONTHLY=price_...
     ```
4. (Optional, for the admin /v1/admin/stats MRR estimate) record the
   monthly price in cents:
   ```
   STRIPE_PRICE_AMOUNT_CENTS=999
   ```
5. Webhooks → Add endpoint.
   - URL: `https://api.evolights.io/v1/billing/webhook`
     (whatever your real public API URL is — Stripe must be able to
     reach this from the public internet; if you're testing pre-DNS, use
     `stripe listen --forward-to ...` from the Stripe CLI.)
   - Events to listen for: in the search box, type `customer.subscription`
     and check `created`, `updated`, `deleted`, `trial_will_end`. Then
     check `checkout.session.completed`.
   - Click "Add endpoint". Reveal the **Signing secret** (`whsec_...`).
   - Paste into `.env`:
     ```
     STRIPE_WEBHOOK_SECRET=whsec_...
     ```

### 5.2 Verify the test flow

After you've finished section 10 (boot the stack):

```bash
# Register a test user
TOKEN=$(curl -s -X POST https://api.evolights.io/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@you.com","password":"testtest8"}' | jq -r .token)

# Start checkout
URL=$(curl -s -X POST https://api.evolights.io/v1/billing/checkout \
  -H "Authorization: Bearer $TOKEN" | jq -r .url)
echo $URL
# Open in a browser. Pay with test card 4242 4242 4242 4242, any future
# expiry, any CVC, any ZIP.

# Tail the API log to watch the webhook arrive:
docker compose logs -f api | grep -i stripe
```

You should see a `customer.subscription.created` event followed by an
update on the subscriptions table. `GET /v1/me` for that user now shows
`sub_status: active`.

If the webhook doesn't arrive: Stripe Dashboard → your endpoint →
"Recent deliveries" tab will show the response body. The most common
failure modes:

- `bad_signature` (400) — `STRIPE_WEBHOOK_SECRET` doesn't match. Copy
  it again from the dashboard, restart the api.
- `missing_raw_body` (400) — should not happen in this codebase, but if
  you've put a reverse proxy between Stripe and the api, ensure it's not
  re-encoding the request body.
- Endpoint times out — check that DNS resolves and your firewall allows
  Stripe's IPs (https://stripe.com/docs/ips).

### 5.3 Switch to production

1. Stripe Dashboard → toggle to **Live mode** (top left).
2. Repeat the steps in 5.1 against the live-mode dashboard:
   - Get a live secret key (`sk_live_...`).
   - Re-create the same product + price (Stripe does NOT share these
     between modes). Copy the new `price_live_...` ID.
   - Re-create the webhook endpoint. Get a new `whsec_live_...` secret.
3. Update credentials. `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` stay
   in `.env` (they're genuine deploy-time secrets), so edit those there and
   restart the api. `STRIPE_PRICE_ID_MONTHLY` is now a runtime setting:
   either edit it in the admin UI (Settings → Stripe → Default monthly price
   ID) or, on first boot, leave the env value as the default.

   `.env`:
   ```
   STRIPE_SECRET_KEY=sk_live_...
   STRIPE_WEBHOOK_SECRET=whsec_live_...
   # STRIPE_PRICE_ID_MONTHLY can stay as the test value here; admin UI override wins.
   ```
4. Restart the API to pick up the new keys:
   ```bash
   docker compose up -d api
   ```
   Then log into the admin UI and set Stripe → Default monthly price ID to
   the live `price_live_...` value. No further restart required.
5. Test with a **real** card on a personal account. Verify:
   - The card was charged (Stripe Dashboard → Payments).
   - `/v1/me` shows `sub_status: active`.
   - The Customer Portal works (`POST /v1/billing/portal` then visit URL,
     try cancelling, confirm webhook arrives, confirm `sub_status` flips).
6. Refund the test charge on the dashboard.

---

## 6. Configure email (optional but strongly recommended)

If you skip this section, password reset will silently no-op (the API
returns 202 either way to prevent enumeration; the user just never gets
the email). Consider it required for any real user base.

Pick exactly one provider via `EMAIL_PROVIDER`. Both can be configured
at the same time but only one is active.

### 6.1 SMTP (most common)

Pick a provider — SendGrid, AWS SES, Mailgun, Postmark, your own server,
or even a Gmail account with an App Password. Get host, port, username,
password.

Two options to apply the config:

**Recommended (no restart):** log into the admin UI → Settings → Email and
fill in Provider=`smtp`, From, SMTP host/port/secure/user/password. Saving
the form invalidates the in-process email transporter; the next
`/v1/auth/forgot-password` rebuilds and verifies it. Failures show up in
the api log as `smtp verify failed — email disabled` and the user just
gets the always-202 response (no email).

**First-boot bootstrap:** if you'd rather seed via env, set the same values
in `.env` then restart the api once. The admin UI overrides anything in
`.env`, so you only need this for fresh installs.

```
EMAIL_PROVIDER=smtp
EMAIL_FROM="EvoLights <noreply@evolights.io>"
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_SECURE=false        # true for port 465 (implicit TLS), false for 587 (STARTTLS)
SMTP_USER=apikey         # SendGrid uses the literal string "apikey"
SMTP_PASS=<your SendGrid API key>
```

### 6.2 Microsoft Graph (if you're already in Microsoft 365)

Sends mail as a real Microsoft 365 mailbox via the Graph
`/users/{upn}/sendMail` endpoint, using the OAuth client-credentials flow.

Setup:

1. Azure Portal → Microsoft Entra ID → App registrations → New
   registration.
   - Name: "EvoLights mail".
   - Supported account types: Accounts in this organizational directory
     only.
   - Click Register.
2. Note the **Application (client) ID** and **Directory (tenant) ID**.
3. Certificates & secrets → New client secret. Copy the value
   immediately (it's hidden after page reload).
4. API permissions → Add a permission → Microsoft Graph → **Application**
   permissions → Mail.Send. Click Add. Then the critical step:
   **Grant admin consent for <tenant>** (button at the top of the
   permissions list). Without admin consent the token request will
   succeed but the sendMail call will 403.
5. Pick a mailbox to send from. It must be a real licensed mailbox in
   the tenant; group / shared mailboxes need Mail.Send extended.

In `.env`:

```
EMAIL_PROVIDER=graph
EMAIL_FROM="EvoLights <noreply@evolights.io>"   # for logging parity
GRAPH_TENANT_ID=<directory tenant id>
GRAPH_CLIENT_ID=<application client id>
GRAPH_CLIENT_SECRET=<the secret you copied in step 3>
GRAPH_SENDER_UPN=noreply@evolights.io           # the licensed mailbox
```

> Note: the Graph send sets the From header to whatever the sending
> mailbox is, regardless of `EMAIL_FROM`. The `EMAIL_FROM` env is kept
> only for log parity with the SMTP path.

### 6.3 Test it

```bash
curl -X POST https://api.evolights.io/v1/auth/forgot-password \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@yourrealemail.com"}'
```

Check your inbox. The link goes to `${PUBLIC_WEB_URL}/reset?token=...`
(set `PUBLIC_WEB_URL` in `.env` if you haven't already; the default is
`https://app.evolights.io`).

If nothing arrives:

```bash
docker compose logs api | grep -i email
```

Look for `email sent` (success), or `forgot-password send failed` (your
provider rejected it — read the inner error).

---

## 7. Configure Sign in with Apple (optional)

Skip if you only want email/password and Google.

1. https://developer.apple.com/account → Identifiers → "+" → App IDs →
   App. Pick a bundle ID (e.g. `io.evolights.app`). Enable "Sign in with
   Apple". Save.
2. Identifiers → "+" → Services IDs. Pick an identifier (e.g.
   `io.evolights.web`) — this is the value Apple uses as `aud` in
   id_tokens for non-native flows. For pure native iOS flows the bundle
   ID itself is the audience; for web/Android you need a Services ID.
3. In `.env`:
   ```
   APPLE_CLIENT_ID=io.evolights.app
   ```
   Use the bundle ID for native iOS; use the Services ID for web. The
   server only verifies that Apple's `aud` claim equals this string.
4. Restart the api. The boot log should NOT print `APPLE_CLIENT_ID not
   set`.

There is no Apple-side webhook to configure; verification is JWKS-based
and handled by the `apple-signin-auth` library.

---

## 8. Configure Sign in with Google (optional)

1. https://console.cloud.google.com → New project (or pick one).
2. APIs & Services → OAuth consent screen. Pick External. Fill in the
   minimum: app name, support email, app logo (optional). Save & continue.
   Add the scopes `userinfo.email` and `userinfo.profile`. Add yourself
   as a test user while you're in dev mode.
3. APIs & Services → Credentials → Create Credentials → OAuth client ID.
   Create one entry per platform you'll support:
   - iOS app: Application type "iOS", bundle ID `io.evolights.app`.
   - Android app: Application type "Android", package name +
     SHA-1 of your signing cert.
   - Web (if you ever build a web app): Application type "Web
     application", redirect URIs as needed.
4. Copy the client IDs into `.env`:
   ```
   GOOGLE_CLIENT_ID_IOS=12345-abc.apps.googleusercontent.com
   GOOGLE_CLIENT_ID_ANDROID=12345-def.apps.googleusercontent.com
   GOOGLE_CLIENT_ID_WEB=12345-ghi.apps.googleusercontent.com
   ```
   At least one must be set for `/v1/auth/google` to be enabled. The API
   accepts any of the three as the token's audience.
5. Restart the api.

When you're ready for production, return to OAuth consent screen and
"Publish app" so non-test users can sign in.

---

## 9. Replace the dev OTA pubkey in firmware

Now your cloud has a production signing key and is ready to sign
manifests. The firmware still trusts whatever pubkey the dev built it
with. Before you push real updates to real customer devices, **rebuild
the firmware with your production pubkey**, otherwise any customer
device that accepts your manifests is also implicitly trusting whoever
built the dev key.

1. From `secrets/ota-prod.b64`, copy the single base64 line (no spaces,
   no newlines).

2. Open the firmware repo (this repo). The pubkey embed point is in
   `firmware/usermods/cloud_relay/` (specifically the OTA verifier when
   the `feat/firmware-signed-ota` branch lands; see the gap note in
   INTEGRATION.md Section 6.3). The constant is named `OTA_PUBKEY_B64`,
   bracketed by anchor comments:

   ```cpp
   // EVOLIGHTS-ANCHOR: ota-pubkey
   static const char OTA_PUBKEY_B64[] PROGMEM = "<paste your base64 here>";
   // EVOLIGHTS-ANCHOR: ota-pubkey-end
   ```

   Replace the existing string between the anchor markers with your
   production pubkey.

3. Bump the firmware version in `firmware/wled00/wled.h`:

   ```c
   #define VERSION 2605012   // YYMMDDB integer; bump it
   ```

4. Commit:

   ```bash
   git add firmware/usermods/cloud_relay/ firmware/wled00/wled.h
   git commit -m "rotate OTA pubkey to production; bump version"
   git push origin <your-branch>
   ```

5. CI builds new firmware artifacts (see `firmware/docs/cicd.instructions.md`
   for what happens). Download the signed `.bin` from the build output.

6. Devices that ship from now on will trust YOUR signing key, not the
   dev one. Devices that have already shipped with the dev key need a
   one-shot OTA-from-dev-key, after which they'll be on production.
   (For an alpha cohort with <100 devices, easier to physically reflash;
   document this lifecycle in your release notes.)

---

## 10. Boot the stack

```bash
docker compose up -d
docker compose logs -f api
```

Watch the boot log. You should see, in order:

```
{"level":30,"time":..., "msg":"applying migration 000001_initial.sql"}
{"level":30,"time":..., "msg":"applying migration 000002_tokens_valid_after.sql"}
... (etc through 000006) ...
{"level":30,"time":..., "msg":"ota signing key loaded"}
{"level":30,"time":..., "msg":"smtp transporter verified"}    # if EMAIL_PROVIDER=smtp
{"level":30,"time":..., "msg":"stripe configured"}
{"level":30,"time":..., "msg":"Server listening at http://0.0.0.0:8080"}
```

Verify health:

```bash
curl http://localhost:8080/health
# {"status":"ok","service":"evolights-cloud-api","version":"dev","uptime_s":12}

curl http://localhost:8080/health/ready
# {"ready":true,"db":true,"mqtt":true}
```

If `mqtt:false`, the api can't talk to the broker — check that the
`api` mosquitto user/password match what you set in section 3.3 and
restart the api.

If `db:false`, postgres failed to come up. Check `docker compose logs
postgres`.

Now put a reverse proxy in front of port 8080 to handle TLS termination
for the public hostname. The README references `nginx`, but Caddy is
typically simpler:

```Caddyfile
api.evolights.io {
  reverse_proxy localhost:8080
}
```

Run Caddy on the host (or as another container on the same compose
network). It will get a Let's Encrypt cert automatically.

---

## 11. Bootstrap your admin account

The first admin needs a manual promote because there's no other admin to
do it for you.

1. Create your account through the normal flow:
   ```bash
   curl -X POST https://api.evolights.io/v1/auth/register \
     -H 'Content-Type: application/json' \
     -d '{"email":"you@evolights.io","password":"<long random pw>"}'
   ```

2. Promote yourself via the CLI (run on the server):
   ```bash
   docker compose exec api npm run admin:promote -- you@evolights.io
   ```

   You should see:
   ```
   promoted you@evolights.io (id=<uuid>) is_admin=true
   ```

3. Verify:
   ```bash
   TOKEN=$(curl -s -X POST https://api.evolights.io/v1/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"you@evolights.io","password":"<your pw>"}' | jq -r .token)

   curl https://api.evolights.io/v1/admin/stats -H "Authorization: Bearer $TOKEN"
   ```

   You should get back a JSON object with user / device / sub counts.
   A `403 admin_required` means the promote didn't take — check the
   email matches exactly (case-insensitive on the CLI side).

Promote any subsequent admins via the API:

```bash
curl -X POST https://api.evolights.io/v1/admin/users/<other-uuid>/promote \
  -H "Authorization: Bearer $TOKEN"
```

---

## 12. Publish your first firmware artifact

After CI has produced a signed `.bin` (Section 9), you need to register
it in the cloud so devices can fetch it.

1. Upload the `.bin` somewhere with a stable, public, browser-fetchable
   URL. Options: AWS S3 / Cloudflare R2 / Backblaze B2 / your own
   nginx-served static directory. The URL must be HTTP or HTTPS —
   plain HTTP is fine because the device verifies the signature, not
   the transport.

2. Compute the SHA-256:
   ```bash
   sha256sum firmware-build.bin
   # e.g.: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  firmware-build.bin
   ```

3. Register it (admin auth required):
   ```bash
   curl -X POST https://api.evolights.io/v1/ota/firmwares \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{
       "version": "0.1.0+ev3",
       "board":   "esp32dev_evolights",
       "channel": "stable",
       "url":     "https://artifacts.evolights.io/fw/0.1.0+ev3/esp32dev_evolights.bin",
       "sha256":  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
     }'
   ```

   The cloud signs `version|url|sha256` with your Ed25519 private key
   and stores the resulting manifest. The response includes the
   signature; you don't need to keep it.

4. Push it to a single device for testing:
   ```bash
   curl -X POST https://api.evolights.io/v1/devices/<device-uuid>/ota/push \
     -H "Authorization: Bearer $USER_TOKEN_OWNING_THE_DEVICE"
   ```

   Watch the device's serial output (or the cloud's `last_seen_at`
   ticking) to confirm it received and applied the update.

The same `version`, `board`, `channel` triple is upsert-keyed — re-running
`POST /v1/ota/firmwares` with the same triple and a new URL/hash
publishes a new signed manifest with the same logical version (useful
for re-signing after a rebuild).

---

## 13. Day-2 ops

### 13.1 Updating the API

```bash
# Pull the new image (if you switched docker-compose.yml to use a
# remote image rather than building locally)
docker compose pull api
docker compose up -d api
```

If you're building locally:

```bash
git pull
docker compose build api
docker compose up -d api
```

Migrations are applied automatically on boot. There is no rollback path
— take a Postgres backup first if the migration is non-trivial.

### 13.2 Postgres backup

```bash
docker compose exec -T postgres \
  pg_dump -U evolights evolights | gzip > backup-$(date +%F).sql.gz
```

Cron this nightly. To restore:

```bash
gunzip < backup-2026-05-01.sql.gz | \
  docker compose exec -T postgres psql -U evolights -d evolights
```

For larger deploys consider `pg_basebackup` + WAL streaming to a
secondary or to S3 via WAL-G. Out of scope for the single-instance
runbook.

### 13.3 Log rotation

Docker's default JSON logging driver does not rotate. Either configure
the daemon's `log-opts`:

```json
// /etc/docker/daemon.json
{ "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
```

(restart the docker daemon after editing) or switch to journald:

```yaml
# docker-compose.yml
services:
  api:
    logging:
      driver: journald
```

### 13.4 Monitoring

The simplest health check is `GET /health/ready`. Point any uptime
monitor (UptimeRobot, BetterStack, your own Prometheus blackbox-exporter)
at it. Alert when:

- `ready: false` for >2 consecutive checks (the api is alive but
  postgres or mosquitto is down — service degraded, can't issue or
  redeem pairing codes).
- `/health` itself doesn't return 200 (api is down — full outage).
- HTTP 5xx rate exceeds N/min (something is broken).

For tracing pairing-flow / sub-flow issues, the api's structured
(pino) logs are the source of truth:

```bash
docker compose logs --since 10m api | jq 'select(.level >= 40)'
```

### 13.5 Rotating MQTT users

Per-device MQTT users are auto-rotated on re-pair (Section 5.1 of
INTEGRATION.md). To force-rotate all of them, you'd need to walk every
device row, mint new creds, push them via `/cloud/pair`-equivalent path,
and remove the old broker entries. There is no operator endpoint for
this today; build it if you ever need to (e.g. after a broker leak).

### 13.6 Stripe webhook re-delivery

If the api was down when Stripe tried to deliver a subscription event,
Stripe retries automatically (up to 3 days). Watch
"Recent deliveries" in the Stripe dashboard for stuck events; you can
manually re-trigger. The API is idempotent on subscription upserts —
delivering the same event twice doesn't double-charge or
double-create rows.

### 13.7 GitHub Container Registry pulls

If the operator pulls images instead of building locally, GHCR will
require a personal access token with `read:packages`:

```bash
echo $GHCR_PAT | docker login ghcr.io -u johnsonflix --password-stdin
docker compose pull
```

---

## 14. Limitations & known gaps

Honest accounting of what's not yet finished. Each one has a track in
this section so an operator decides what's acceptable for their
launch window.

### 14.1 Firmware-side MQTT TLS

**Status:** plain TCP today, no TLS. **Tracked:** comment block at the
top of `firmware/usermods/cloud_relay/cloud_relay.cpp`. **Mitigation:**
see Section 4.5 above. **Resolution:** swap `WiFiClient` for
`WiFiClientSecure` and pipe `g_caCertPem` through. Blocked by usermod
build-scope visibility of `WiFiClientSecure`.

### 14.2 Firmware-side OTA verifier

**Status:** the cloud signs and publishes manifests; the firmware
subscriber that verifies and applies is on a feature branch
(`feat/firmware-signed-ota`) and not yet merged to `evolights/main`.
**Impact:** `POST /v1/devices/:id/ota/push` will succeed and the device
receives the manifest, but does nothing with it until that branch
lands. **Resolution:** finish, review, and merge the branch.

### 14.3 No admin web UI

**Status:** all `/v1/admin/*` endpoints exist but you operate them via
curl / Postman / a thin internal tool of your own choosing. **Impact:**
admin operations require a JWT plus a willingness to use a CLI.
**Resolution:** build a small admin SPA (React/Svelte/HTMX, doesn't
matter), gate it behind a CORS allowlist for the operator's office /
VPN. Out of scope for v1 ship.

### 14.4 No OTA release-engineer co-signature

**Status:** today, possession of an admin JWT lets you publish a
firmware manifest that the cloud will sign with the OTA private key.
A single compromised admin password could push malware to every paired
device. **Resolution (planned):** require an offline Ed25519 signature
on `version|url|sha256` in the request body, signed by a release-
engineer hardware token. The cloud verifies this against a registered
release-engineer pubkey BEFORE counter-signing. **Mitigation today:**
keep your admin password in a hardware-backed manager (1Password +
hardware key), rotate quarterly, never log in from a personal device.

### 14.5 No multi-region / HA

**Status:** single Docker host. Postgres, Mosquitto, and the api all
run on the same box. **Resolution:** real HA needs Postgres replication
(Patroni / pgBouncer / a managed PG), broker clustering (Mosquitto
doesn't cluster well — switch to EMQX or VerneMQ), and converting the
in-process pending-relay map to Redis pub/sub. Don't tackle this until
the customer count justifies it.

### 14.6 Subscription plan is hard-coded

**Status:** `STRIPE_PRICE_ID_MONTHLY` is the only price the checkout
endpoint uses. Multi-tier (annual, family, etc.) requires extending
`POST /v1/billing/checkout` to accept a `price_id` parameter and
validating it's in an allowed set. **Resolution:** cheap; do it when
you actually have a tier story.

### 14.7 No bounce / DLR handling

**Status:** the email service abstraction sends mail and trusts the
provider to deliver it. If Mailgun returns "delivered" but the user
never sees it (spam folder, full mailbox, etc.), the api never knows.
**Resolution:** wire in your provider's webhook (most have one) into a
new `/v1/webhooks/email` endpoint, persist bounces, and surface them in
admin. **Mitigation today:** monitor your provider's dashboard.

### 14.8 No device telemetry / fleet view

**Status:** `last_seen_at` is the only telemetry. There's no
log-shipping from devices to the cloud, no "what firmware version is
running on each device" history, no error reporting. **Resolution:**
the broker already has a `evolights/<id>/log` topic per device (ACL'd
write-only); subscribe to it from the cloud and persist a rolling
window. Out of scope for v1.

### 14.9 OAuth account linking

**Status:** `findOrLinkOrCreateUser` will refuse with
`account_link_conflict` if a user signs in with Google and the email
matches an account that already has a different `apple_sub` or
`google_sub`. There is no "merge accounts" UX. **Resolution:** an
admin can manually update the user row; eventually build a "verify
ownership of both" flow. Affected users are rare (someone who used
both providers with the same Gmail).

### 14.10 Pairing is bound to chip_id (not hardware-attested)

**Status:** the device sends its own `chip_id` (ESP32 eFuse MAC) in
`/v1/devices/redeem`. We refuse to silently transfer a paired
hardware-id to a different account, but we trust the device's
self-reported MAC. A bad actor with a stolen pairing code AND control
of an ESP32 could spoof a different chip_id and pair their hardware to
the victim's account. **Resolution (planned):** ESP32 secure boot +
device-attestation cert. Out of scope.

---

## Appendix A — Quick reference: all environment variables

> Vars marked **runtime** are first-boot defaults. Once the api is up, an
> admin can override them in the admin UI's Settings page (DB takes
> precedence over env). The other vars stay env-only — they're either
> genuine deploy-time secrets or container-shape configuration.

| Var | Required | Runtime-editable? | Notes |
|---|---|---|---|
| `NODE_ENV` | rec. | no | `production` in prod |
| `PORT` | rec. | no | Default 8080 |
| `JWT_SECRET` | **yes** | no | ≥32 chars; rotation logs everyone out |
| `PAIRING_CODE_TTL_SECONDS` | no | yes (Behavior) | Default 300 (5 min) |
| `BRAND_NAME` | no | yes (Branding) | Default `EvoLights`; appears in emails |
| `PUBLIC_WEB_URL` | rec. | yes (Public) | Used in password-reset emails |
| `PUBLIC_API_URL` | rec. | yes (Public) | Returned in `/v1/pairing/codes` for devices to call |
| `POSTGRES_*` | **yes** | no |  |
| `DATABASE_URL` | **yes** | no | Must match the POSTGRES_* values |
| `MQTT_URL` | **yes** | no | `mqtt://mosquitto:1883` (internal) |
| `MQTT_API_USERNAME` / `_PASSWORD` | **yes** | no | Cloud's broker creds; must exist in `passwd` |
| `MQTT_PUBLIC_HOST` | rec. | yes (Public) | Broker hostname returned in pairing payload |
| `MQTT_PUBLIC_PORT` | no | yes (Public) | Default 8883 |
| `MQTT_CA_PEM_PATH` | rec. | yes (Public) | Path to broker CA bundle; UI accepts the PEM body directly |
| `MOSQUITTO_DIR` | no | no | Default `/mosquitto-config` |
| `MOSQUITTO_CONTAINER` | no | no | Default `evolights-cloud-mosquitto-1` |
| `STRIPE_SECRET_KEY` | **yes** | no | `sk_live_...` in prod |
| `STRIPE_WEBHOOK_SECRET` | **yes** | no |  |
| `STRIPE_PRICE_ID_MONTHLY` | **yes** | yes (Stripe) | The default subscription price |
| `STRIPE_PRICE_AMOUNT_CENTS` | no | yes (Stripe) | For MRR estimate in admin stats |
| `BILLING_SUCCESS_URL` | no | no | Default `evolights://billing/success?session_id={CHECKOUT_SESSION_ID}` |
| `BILLING_CANCEL_URL` | no | no | Default `evolights://billing/cancel` |
| `BILLING_PORTAL_RETURN_URL` | no | no | Default `evolights://billing/return` |
| `OTA_SIGNING_KEY_PATH` | **yes** | no | Path inside the api container to your `.key` |
| `EMAIL_PROVIDER` | rec. | yes (Email) | `smtp` or `graph` |
| `EMAIL_FROM` | rec. (with provider) | yes (Email) | RFC 5322 From header |
| `SMTP_HOST` / `_PORT` / `_SECURE` / `_USER` / `_PASS` | per provider | yes (Email) | `_PASS` is secret-redacted in API responses |
| `GRAPH_TENANT_ID` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_SENDER_UPN` | per provider | yes (Email) | `_CLIENT_SECRET` is secret-redacted |
| `APPLE_CLIENT_ID` | no | yes (OAuth) | Enables `/v1/auth/apple` |
| `GOOGLE_CLIENT_ID_IOS` / `_ANDROID` / `_WEB` | no | yes (OAuth) | Any one enables `/v1/auth/google` |
| `RELAY_ACK_TIMEOUT_MS` | no | yes (Behavior) | Default 5000 |
| `CORS_ORIGIN` | no | yes (Security, restart req'd) | Comma-separated allowlist; default deny-all (mobile is unaffected) |
| `APP_VERSION` | no | no | Surfaced in `/health` |

---

## Appendix B — Routine checklist (post-deploy)

Run through this once after every prod deploy:

- [ ] `curl https://api.evolights.io/health/ready` → `{"ready":true,"db":true,"mqtt":true}`
- [ ] Register a fresh test account; confirm 201 + JWT.
- [ ] Hit `GET /v1/me` with that JWT; confirm 200.
- [ ] Run `POST /v1/billing/checkout`, complete with a real card,
      verify webhook fired (Stripe dashboard → Recent deliveries → 200).
- [ ] Verify `sub_status: active` on `GET /v1/me`.
- [ ] `POST /v1/auth/forgot-password` for the test account; verify
      email arrived.
- [ ] If you changed the OTA pubkey: confirm at least one
      already-deployed device successfully verified and applied a
      signed manifest (re-flash from the dev pubkey to prod first).
- [ ] Refund the Stripe charge.
- [ ] Soft-delete the test account via `DELETE /v1/admin/users/<uuid>`.
