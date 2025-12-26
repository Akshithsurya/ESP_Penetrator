# ESP32 / ESP8266 Security Suite Manual

## ⚠️ Legal Disclaimer

**WARNING: This software is a security testing tool intended for educational purposes and authorized testing only.**

- Use strictly on networks you own or have explicit permission to audit.
- Misuse to disrupt networks you do not own is illegal.
- The authors assume no liability for misuse of this code.

---

## 📖 Introduction

This firmware provides a comprehensive suite of WiFi penetration testing tools for the ESP32 and ESP8266 platforms. It includes features for reconnaissance, active attacks, credential harvesting (Evil Portal), and packet monitoring (Sniffer).

---

## 🔧 Hardware Requirements

### For ESP32 Version
- **Board:** ESP32 DevKit, NodeMCU-32S, WROOM-32, or similar.
- **RAM:** Standard built-in RAM is sufficient.
- **Features:** Dual-core processing provides stable packet injection and sniffer operations simultaneously.

### For ESP8266 Version
- **Board:** NodeMCU 1.0 (ESP-12E), Wemos D1 Mini, or similar.
- **RAM:** Limited resources available. High packet rates may cause watchdog resets.
- **Dependencies:** Requires `user_interface.h` for raw packet injection and promiscuous mode.
- **Limitations:**
  - "Host Scan" relies on SoftAP station count. It cannot display specific Client MAC addresses due to SDK limitations on this platform.

---

## 💻 Software Requirements

- **Arduino IDE:** Version 1.8.x or newer.
- **Board Manager:**
  - For ESP32: Install `esp32` by Espressif Systems.
  - For ESP8266: Install `esp8266` by Espressif Systems.
- **Libraries:** Standard libraries included with the core installation (No external download required):
  - `WiFi.h` / `ESP8266WiFi.h`
  - `WebServer.h` / `ESP8266WebServer.h`
  - `DNSServer.h`

---

## 📥 Installation

1. Download the appropriate `.ino` file (`ESP32_kill.ino` or `ESP8266_kill.ino`).
2. Open the file in the Arduino IDE.
3. Select your Board: **Tools > Board > Generic ESP8266 Module** or **ESP32 Dev Module**.
4. Select the correct Upload Speed: **115200**.
5. Click the **Upload** button.

---

## 🚀 First Boot & Access

1. Connect the microcontroller to power.
2. Use a WiFi-enabled device (Laptop, Phone) to search for wireless networks.
3. Connect to the Access Point named: **TTAN_PenTest**
4. Enter the password: **pentester123**
5. Open a web browser and navigate to: **http://192.168.4.1**
6. The Main Dashboard will load.

**Note:** The Admin Panel (for viewing captured credentials) is available at **http://192.168.4.1:8080**

---

## 🖥️ Web Interface Guide

The dashboard is divided into three main sections: **System Status**, **Reconnaissance**, and **Attacks & Tools**.

### 1. Reconnaissance

This section allows you to gather information about the local WiFi environment.

#### WiFi Scan:
- Initiates a scan for nearby Access Points.
- **Important:** The ESP must briefly disconnect from its own AP to scan. The screen will display a "Scanning..." message and automatically reload when finished. Do not change your device's WiFi connection during this time.
- **Results:** Displays SSID, Signal Strength, Channel, BSSID, and Encryption type.

#### Host Scan:
- Displays the number of clients currently connected to the ESP's Access Point.
- **Note:** On ESP8266, specific MAC addresses of clients are not displayed.

---

### 2. Attacks & Tools

This section contains controls for executing various attacks. Use the Channel dropdown to select the target frequency (1-13).

#### Monitor Mode:
- **Channel Analysis:** Locks the device to a specific channel and displays packet statistics (Management, Control, Data).
- **Channel Hopper:** Cycles through channels 1-13 automatically to capture traffic across the spectrum.

#### Deauth (Scan Required):
- Found in the "Scan Results" table next to a target network.
- Clicking this sends forged 802.11 Deauthentication frames.
- **Effect:** Forces connected clients to disconnect from the target AP.

#### Beacon Flood:
- Sends continuous fake Beacon frames.
- **Effect:** Creates hundreds of fake Access Points with the chosen SSID, confusing scanners and users.

#### Probe Flood:
- Sends continuous fake Probe Request frames.
- **Effect:** Spamming the airwaves to detect target networks or create noise.

#### PMKID Capture:
- Listens for Robust Security Network (RSN) information frames.
- Useful for capturing hashes without a client handshake.

#### Handshake Capture:
- Puts the device in promiscuous mode to record WPA/WPA2 4-way handshakes.
- **Usage:** Start capture, then run a Deauth attack against a client to force them to reconnect.
- **View:** Click "View Handshakes" to see the captured packet logs.

#### Evil Portal (Captive Portal):
- Prompts for a Fake SSID (e.g., Starbucks_WiFi).
- The ESP reboots its AP with this new name.
- The DNS server is activated to redirect all traffic to a fake login page.
- **Harvesting:** Users enter credentials thinking they are logging in to the real network.
- **View Data:** Go to Port 8080 (`/admin`) to see captured usernames and passwords.

#### Karma Attack:
- Responds to all Probe Requests from nearby devices.
- **Effect:** Tricks devices into thinking the ESP is their known home network, forcing a connection.

---

## 🛠️ Troubleshooting

### Scan Button Fails / Page Unavailable
- **Cause:** The device switches modes to scan, dropping the client connection.
- **Solution:** The code has been updated to show an interstitial "Scanning..." page. Wait 10-15 seconds for the device to restore its AP and the page to reload automatically.

### ESP8266 Stability / Guru Meditation Error
- **Cause:** The ESP8266 has less processing power and RAM than the ESP32. Handling web traffic while injecting packets can trigger the Watchdog Timer (WDT).
- **Solution:**
  - Increase the `WATCHDOG_TIMEOUT` in Config (if defined).
  - If the device crashes, reduce the number of active attacks.
  - Ensure you are not running the Serial Monitor at too slow a baud rate while attacks are active.

### Attacks Not Working
- **Channel Mismatch:** Ensure the "Channel" dropdown matches the target AP's channel.
- **Signal Strength:** If the ESP is too far away, it will not hear packets from the target, nor will the target hear the ESP's Deauth packets.
- **Protection:** Some modern routers have frame flooding protection, which may block Deauth or Beacon floods.

### Admin Panel / Captured Credentials
If you are running the Evil Portal, open a separate tab to **http://192.168.4.1:8080/admin** to view captured data in real-time without disrupting the victim's view of the portal.

---

## 🔌 API Endpoints Reference

### Main Server (Port 80)
- `GET /`: Main Dashboard
- `GET /s`: Start WiFi Scan
- `GET /h`: Start Host Scan
- `GET /d?m=...`: Start Deauth (Arguments: `m=MAC`, `s=SSID`, `c=Channel`)
- `GET /stop`: Stop all active attacks
- `GET /r`: Reboot the device

### Admin Server (Port 8080)
- `GET /admin`: View captured credentials table
- `GET /admin/json`: Download credentials as JSON
- `GET /admin/clear`: Wipe all captured data

---

## 🔄 Porting Notes (ESP32 vs ESP8266)

| Feature | ESP32 Implementation | ESP8266 Implementation |
|---------|---------------------|------------------------|
| Low-Level Access | `esp_wifi.h` (Official IDF) | `user_interface.h` (RTOS SDK) |
| Packet Injection | `esp_wifi_80211_tx` | `wifi_send_pkt_freedom` |
| Sniffer Callback | Struct with metadata (RSSI, Rate) | Raw buffer (buf, len) only |
| Performance | High stability (Dual Core) | Moderate (Single Core) |

---

## 👤 Credits

- **Version:** 2.4
- **Author:** TTAN
- **License:** Educational Use Only

---

## ⭐ Support

If you find this project useful, please consider giving it a star on GitHub!

---

**Remember:** Always use responsibly and ethically. Only test on networks you own or have explicit written permission to test.
