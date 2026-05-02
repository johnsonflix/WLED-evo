#include "wled.h"

#if !defined(ARDUINO_ARCH_ESP32)
  // The cloud relay is ESP32-only: TLS+MQTT+rendering exceeds ESP8266 budget.
  // Provide a no-op stub so the usermod can still be referenced in the build.
  class EvoLightsCloudRelay : public Usermod {
   public:
    void setup() override {}
    void loop()  override {}
    uint16_t getId() override { return 0xE001; }
  };
  static EvoLightsCloudRelay evolights_cloud_relay;
  REGISTER_USERMOD(evolights_cloud_relay);
#else

// wled.h (above) transitively provides ArduinoJson, ESPAsyncWebServer, and WiFi.
// Including them again here would fail because PIO compiles usermods in an
// isolated library scope that doesn't see WLED's vendored deps directly.
#include "wled_cloud_auth.h"
#include <PubSubClient.h>
#include <HTTPClient.h>

/*
 * EvoLights Cloud Relay
 *
 * Outbound MQTT bridge. After pairing, the device connects to the EvoLights
 * cloud broker and subscribes to its per-device command topic. Commands
 * arriving over MQTT are dispatched into the local HTTP stack with the
 * EvoAuth cloud-trusted token, so they bypass the local auth gate.
 *
 * !!! TLS TODO !!!
 * Currently uses plain WiFiClient (no TLS). The original design called for
 * MQTT-over-TLS on port 8883, but WLED's build system makes WiFiClientSecure
 * unreachable from a usermod's compile scope. Plain TCP is a placeholder so
 * the rest of the architecture can ship; before any production release we
 * MUST swap in TLS. Per-device auth (mqtt_user/mqtt_pass) still works, but
 * a passive eavesdropper sees credentials in the clear.
 */

namespace EvoLights {

namespace {

  // ---- persisted state (mirrored to wsec.json) ----
  bool   g_enabled = false;
  String g_brokerHost;       // "mqtts.evolights.io"
  uint16_t g_brokerPort = 8883;
  String g_deviceId;         // server-assigned uuid
  String g_mqttUser;
  String g_mqttPass;
  String g_caCertPem;        // root CA pem for the broker

  // ---- runtime state ----
  WiFiClient g_tcp;          // TODO: swap to TLS client (see file header note)
  PubSubClient *g_mqtt = nullptr;
  bool g_connected = false;
  uint32_t g_nextReconnectAt = 0;
  String g_topicCmd;
  String g_topicState;
  String g_topicOta;

  // ---- helpers ----
  String topicFor(const char *suffix) {
    String t = F("evolights/");
    t += g_deviceId;
    t += '/';
    t += suffix;
    return t;
  }

  void publishState(JsonDocument &doc) {
    if (!g_connected || !g_mqtt) return;
    String s; serializeJson(doc, s);
    g_mqtt->publish(g_topicState.c_str(), s.c_str(), false);
  }

  // Dispatch an MQTT command into the local HTTP stack via loopback.
  // Body schema: {"id":"<corr-id>","path":"/json/state","method":"POST","body":{...}}
  void onCmdMessage(char* /*topic*/, byte *payload, unsigned int len) {
    StaticJsonDocument<2048> doc;
    if (deserializeJson(doc, payload, len)) return;
    const char *id     = doc["id"]     | "";
    const char *path   = doc["path"]   | "/json/state";
    const char *method = doc["method"] | "GET";
    JsonVariant body   = doc["body"];

    HTTPClient http;
    String url = "http://127.0.0.1";
    url += path;
    if (!http.begin(url)) return;
    // Stamp the cloud-trusted token so the EvoAuth gate lets us through.
    http.addHeader(F("X-EvoLights-Token"), EvoAuth::cloudTrustedToken());
    http.addHeader(F("Content-Type"), F("application/json"));

    int code;
    String resp;
    if (strcasecmp(method, "POST") == 0) {
      String b; if (!body.isNull()) serializeJson(body, b);
      code = http.POST(b);
    } else {
      code = http.GET();
    }
    if (code > 0) resp = http.getString();
    http.end();

    StaticJsonDocument<2048> reply;
    reply["id"]     = id;
    reply["status"] = code;
    reply["body"]   = serialized(resp.length() ? resp : String("null"));
    publishState(reply);
  }

  void connectMqtt() {
    if (!g_enabled || g_brokerHost.length() == 0 || g_deviceId.length() == 0) return;
    if (millis() < g_nextReconnectAt) return;
    g_nextReconnectAt = millis() + 5000;

    if (!g_mqtt) {
      g_mqtt = new PubSubClient(g_tcp);
      g_mqtt->setBufferSize(4096);
      g_mqtt->setCallback(onCmdMessage);
    }
    g_mqtt->setServer(g_brokerHost.c_str(), g_brokerPort);
    // TODO TLS: when WiFiClientSecure is wired in, gate on g_caCertPem and
    // call g_tls.setCACert(g_caCertPem.c_str()) here. Today we connect plain.

    String clientId = String(F("evo-")) + g_deviceId;
    if (g_mqtt->connect(clientId.c_str(), g_mqttUser.c_str(), g_mqttPass.c_str())) {
      g_connected = true;
      g_topicCmd   = topicFor("cmd");
      g_topicState = topicFor("state");
      g_topicOta   = topicFor("ota");
      g_mqtt->subscribe(g_topicCmd.c_str(),  1);
      g_mqtt->subscribe(g_topicOta.c_str(),  1);
      EvoAuth::setCloudBypassEnabled(true);
      // Announce ourselves.
      StaticJsonDocument<256> hello;
      hello["event"] = "online";
      hello["fw"]    = String(VERSION);
      publishState(hello);
      Serial.println(F("[CloudRelay] connected"));
    } else {
      g_connected = false;
      Serial.printf("[CloudRelay] connect failed rc=%d\n", g_mqtt->state());
    }
  }

  void disconnectAndForget() {
    if (g_mqtt && g_mqtt->connected()) g_mqtt->disconnect();
    g_connected = false;
    EvoAuth::setCloudBypassEnabled(false);
    g_brokerHost = ""; g_brokerPort = 8883;
    g_deviceId = ""; g_mqttUser = ""; g_mqttPass = ""; g_caCertPem = "";
    serializeConfigSec();
  }

  // -----------------------------------------------------------------
  // Pairing flow — POST /cloud/pair
  // The app sends { code, cloud_api } and this device redeems the code with
  // the cloud to receive { device_id, broker_host, broker_port, mqtt_user,
  // mqtt_pass, ca_cert }.
  // -----------------------------------------------------------------
  void handlePair(AsyncWebServerRequest *request, JsonObject &body) {
    const char *code     = body["code"]      | "";
    const char *apiUrl   = body["cloud_api"] | "";
    if (!*code || !*apiUrl) {
      request->send(400, F("application/json"), F("{\"error\":\"missing code or cloud_api\"}"));
      return;
    }

    HTTPClient http;
    String url = String(apiUrl) + F("/v1/devices/redeem");
    if (!http.begin(url)) {
      request->send(502, F("application/json"), F("{\"error\":\"cloud unreachable\"}"));
      return;
    }
    http.addHeader(F("Content-Type"), F("application/json"));
    StaticJsonDocument<256> req;
    req["code"]        = code;
    req["fw_version"]  = VERSION;
    req["chip_id"]     = String((uint32_t)ESP.getEfuseMac(), HEX);
    String reqBody; serializeJson(req, reqBody);
    int rc = http.POST(reqBody);
    String resp = http.getString();
    http.end();

    if (rc != 200) {
      request->send(rc > 0 ? rc : 502, F("application/json"), resp);
      return;
    }

    StaticJsonDocument<3072> doc;
    if (deserializeJson(doc, resp)) {
      request->send(502, F("application/json"), F("{\"error\":\"invalid cloud response\"}"));
      return;
    }
    g_deviceId    = doc["device_id"].as<String>();
    g_brokerHost  = doc["broker_host"].as<String>();
    g_brokerPort  = doc["broker_port"] | 8883;
    g_mqttUser    = doc["mqtt_user"].as<String>();
    g_mqttPass    = doc["mqtt_pass"].as<String>();
    g_caCertPem   = doc["ca_cert"].as<String>();
    g_enabled     = true;
    serializeConfigSec();
    g_nextReconnectAt = 0; // try connecting on next loop tick

    request->send(200, F("application/json"),
      String(F("{\"ok\":true,\"device_id\":\"")) + g_deviceId + F("\"}"));
  }

  // -----------------------------------------------------------------
  // wsec.json hooks
  // -----------------------------------------------------------------
  void readFromWsec(JsonObjectConst evo) {
    if (evo.isNull()) return;
    g_enabled    = evo["enabled"]   | false;
    g_brokerHost = evo["host"]      | "";
    g_brokerPort = evo["port"]      | 8883;
    g_deviceId   = evo["device_id"] | "";
    g_mqttUser   = evo["user"]      | "";
    g_mqttPass   = evo["pass"]      | "";
    g_caCertPem  = evo["ca"]        | "";
  }

  void writeToWsec(JsonObject evo) {
    evo["enabled"]   = g_enabled;
    evo["host"]      = g_brokerHost;
    evo["port"]      = g_brokerPort;
    evo["device_id"] = g_deviceId;
    evo["user"]      = g_mqttUser;
    evo["pass"]      = g_mqttPass;
    evo["ca"]        = g_caCertPem;
  }

} // anonymous namespace

class CloudRelay : public Usermod {
 private:
  bool routesRegistered = false;

  void registerRoutes() {
    if (routesRegistered) return;
    routesRegistered = true;

    // POST /cloud/pair  — body: { code, cloud_api }
    AsyncCallbackJsonWebHandler *pairHandler = new AsyncCallbackJsonWebHandler(
      "/cloud/pair",
      [](AsyncWebServerRequest *request, JsonVariant &json) {
        JsonObject obj = json.as<JsonObject>();
        handlePair(request, obj);
      });
    server.addHandler(pairHandler);

    // POST /cloud/unpair
    server.on("/cloud/unpair", HTTP_POST, [](AsyncWebServerRequest *request) {
      disconnectAndForget();
      request->send(200, F("application/json"), F("{\"ok\":true}"));
    });

    // GET /cloud/status
    server.on("/cloud/status", HTTP_GET, [](AsyncWebServerRequest *request) {
      String s = String(F("{\"paired\":")) + (g_enabled ? "true" : "false")
               + F(",\"connected\":") + (g_connected ? "true" : "false")
               + F(",\"broker\":\"") + g_brokerHost + F(":") + String(g_brokerPort) + F("\"")
               + F(",\"device_id\":\"") + g_deviceId + F("\"}");
      request->send(200, F("application/json"), s);
    });
  }

 public:
  void setup() override {
    registerRoutes();
  }

  void connected() override {
    g_nextReconnectAt = 0; // attempt MQTT shortly after WiFi comes up
  }

  void loop() override {
    if (!g_enabled) return;
    if (!WLED_CONNECTED) return;
    if (!g_connected || !g_mqtt || !g_mqtt->connected()) {
      connectMqtt();
      return;
    }
    g_mqtt->loop();
  }

  uint16_t getId() override { return 0xE001; }   // unused range; not in const.h yet

  // Shoehorn our wsec.json read/write into the standard usermod readFromConfig
  // hook by mirroring it. cfg.cpp doesn't currently call usermod hooks for
  // wsec.json, so we register dedicated calls below from this usermod's
  // setup() via a small bridge — TODO once cfg.cpp gains that hook. For the
  // meantime, the cloud_relay storage is held in cfg.json under "um".
  void addToConfig(JsonObject &root) override {
    JsonObject top = root.createNestedObject(F("EvoCloudRelay"));
    writeToWsec(top);
  }
  bool readFromConfig(JsonObject &root) override {
    return readFromWsec(root[F("EvoCloudRelay")]), true;
  }
};

static CloudRelay evolights_cloud_relay;
REGISTER_USERMOD(evolights_cloud_relay);

} // namespace EvoLights

#endif // ARDUINO_ARCH_ESP32
