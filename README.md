# ESP_Penetrator
for hackingusing ESP_8266 nodemcu 1.0 & esp32 
using arduino ide 
# educational purposes only please don't use on other's wifi
#manual :


ESP32 / ESP8266 WiFi Security Suite (TTAN_PenTest)
VersionPlatform

A comprehensive penetration testing toolkit for ESP32 and ESP8266 microcontrollers. It includes capabilities for WiFi scanning, Deauthentication attacks, Beacon/Probe flooding, Evil Portal (Captive Portal), WPA2 Handshake/PMKID capturing, and packet monitoring (Sniffer).

⚠️ LEGAL DISCLAIMER & WARNING
IMPORTANT: This tool is intended for authorized educational purposes and security testing only.

Use only on networks you own.
Do not use this tool to disrupt networks you do not have explicit permission to test.
Unauthorized access to computer networks is illegal.
The developers are not responsible for any misuse of this software.
By compiling and using this code, you agree to these terms.

Features
Reconnaissance
WiFi Scan: Scans for nearby Access Points, displaying SSID, Signal (dBm), Channel, BSSID, and Encryption type.
Host Scan: Displays connected clients to the ESP's Access Point.
Attacks
Deauth Attack: Disconnects clients from a target AP using forged 802.11 Deauthentication frames.
Disassociation Attack: Disconnects clients using forged Disassociation frames.
Association Flood: Floods a target AP with fake association requests to exhaust its resources.
Authentication Flood: Floods a target AP with fake authentication frames.
Beacon Flood: Creates hundreds of fake Access Points (SSID spam) to confuse scanners.
Probe Flood: Floods the air with Probe Request frames.
Karma (Mana) Attack: Responds to all Probe Requests, mimicking known SSIDs to force clients to connect to the device.
Capturing & Monitoring
Handshake Capture: Monitors traffic to capture WPA/WPA2 4-way handshakes for offline cracking.
PMKID Capture: Captures the Robust Secure Network Key (RSN) information.
Packet Sniffer: Raw 802.11 packet capture and analysis.
Channel Monitor: Displays real-time packet statistics (Management, Control, Data frames).
Channel Hopper: Automatically hops through channels 1-13 to gather data across the spectrum.
Social Engineering
Evil Portal (Captive Portal): Creates a fake AP that forces users to a login page ("Public WiFi Registration") to harvest credentials.
Admin Panel: Separate web interface (Port 8080) to view captured credentials.
Hardware Requirements
For ESP32 Code (ESP32_kill.ino)
Microcontroller: ESP32 (e.g., ESP32-WROOM-32, DOIT DevKit v1, NodeMCU-32S).
Flash: Minimum 4MB.
RAM: Built-in RAM is sufficient.
For ESP8266 Code (ESP8266_kill.ino)
Microcontroller: ESP8266 (e.g., NodeMCU v1.0, Wemos D1 Mini).
Flash: Minimum 4MB recommended.
RAM: Note: ESP8266 has less RAM than ESP32. Large scans or high packet rates may cause instability.
Limitations:
Host Scan (Hosts) does not return client MAC addresses on ESP8266 due to Arduino SDK limitations (it relies on SoftAP station count only).
Software Requirements
Arduino IDE: Version 1.8.x or 2.x.x.
Core Libraries:
For ESP32: Install esp32 by Espressif Systems (via Board Manager).
For ESP8266: Install esp8266 by Espressif Systems (via Board Manager).
Included Dependencies (Standard Arduino Libraries):
WiFi.h (or ESP8266WiFi.h)
WebServer.h (or ESP8266WebServer.h)
DNSServer.h
Special Dependencies (for raw packet injection):
ESP32: esp_wifi.h (Included in ESP32 Core).
ESP8266: user_interface.h (Included in ESP8266 Non-OS SDK functions).
Installation & Compilation
Clone or Download the repository.
Open the .ino file in Arduino IDE (ESP32_kill.ino or ESP8266_kill.ino).
Select Board:
Go to Tools > Board > esp32 (or esp8266).
Select your specific board model (e.g., NodeMCU-32S or NodeMCU 1.0 (ESP-12E Module)).
Select Upload Speed: 921600 (usually works best).
Click Upload.
First Boot & Connection
Power on your device.
Connect your computer or smartphone to the WiFi Access Point named: TTAN_PenTest
Password: pentester123
Once connected, open your web browser and navigate to:
http://192.168.4.1 (Main Interface)
http://192.168.4.1:8080 (Admin/Captive Panel)
The IP is also printed to the Serial Monitor (115200 baud).
Usage Guide
1. WiFi Scan & Target Selection
Click "WiFi Scan" in the Reconnaissance section.
Note on Connectivity: The ESP32/8266 must briefly disconnect from AP mode to perform a Station scan. The code handles this by showing a "Scanning..." page and automatically reloading when complete.
Results will appear in the "SCAN RESULTS" box.
Each network has action buttons (DEAUTH, DISASSOC, ASSOC, AUTH) pre-filled with the target MAC, Channel, and SSID.
2. Running Attacks
Select the Target Channel using the dropdown menu in the "Attacks & Tools" section.
Deauth/Disassoc: Use the buttons from the scan results (or manually call the API) to start kicking clients.
Beacon/Probe Floods: Click the "Beacon/Probe Flood" buttons. You may be prompted to enter an SSID. The ESP will begin spamming frames immediately.
Monitor/Sniffer: Click to start listening to the air. Use "Channel Hopper" to cycle through all channels.
3. Handshake / PMKID Capture
Select the channel your target is on.
Click "Handshake Capture".
The device will enter promiscuous mode.
Trigger a client to reconnect (e.g., run a Deauth attack).
If successful, the captured handshake frames are logged.
Click "View Handshakes" to see the raw capture logs.
4. Evil Portal (Credential Harvesting)
Click "Evil Portal".
Enter a fake SSID (e.g., Starbucks_WiFi, Airport_Free).
The ESP will reboot its AP with the new name.
DNS Server starts automatically, redirecting all HTTP traffic to the login page.
Victims see a "Public WiFi Registration" form.
View captured credentials at http://192.168.4.1:8080/admin.
Troubleshooting
"WiFi Scan" not available / Connection timeout
Cause: The device disconnects from the AP to scan, breaking the browser connection.
Fix: The code now includes an interstitial "Scanning..." page that handles the reload automatically. Ensure you do not manually switch WiFi networks on your device while scanning.
Attacks not working (Deauth fails)
Ensure you are on the correct Channel.
Ensure the Target BSSID is correct.
Check Signal Strength: If the ESP is too far from the target, the target won't "hear" the packets.
ESP8266 Specifics: Use wifi_set_power(82) in setup for max range.
Web Interface is slow
ESP8266: Handling raw frames + Web Server can tax the CPU. If the interface lags, stop the packet injection attacks.
Serial Monitor shows "Guru Meditation Error" (ESP8266)
This is a Watchdog Timer Reset (WDT).
Fix: Ensure ESP.wdtFeed() is called frequently in the loop() (included in the code). If it still crashes, you might be flooding too fast for the CPU to handle the web server.
File Structure & API
Main Server (Port 80)
/ : Dashboard.
/s : Initiate WiFi Scan.
/h : Initiate Host Scan.
/m?c=1&hop=1 : Start Monitor/Hopper.
/d?m=... : Start Deauth.
/handshake : View captured handshakes.
Admin Server (Port 8080)
/admin : View captured credentials (Name/Mobile).
/admin/json : Export credentials as JSON.
Notes on Porting (ESP32 vs ESP8266)
Feature	ESP32 Implementation	ESP8266 Implementation
Low-level Access	esp_wifi.h (Official ESP-IDF)	user_interface.h (SDK)
Packet Injection	esp_wifi_80211_tx	wifi_send_pkt_freedom
Sniffer Callback	wifi_promiscuous_pkt_t*	uint8_t* buf, uint16_t len
Stability	High (Dual Core)	Medium (Single Core, share memory)
Credits & Version
Version: 2.4
Author: TTAN
Contributors: Open Source Community
License: Educational Use Only.
