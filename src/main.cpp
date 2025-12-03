/*
 * Network Analyzer - WiFi Network Monitor & Analyzer
 * --------------------------------------------------
 * Author: Carl Schofield
 * Date: November 2025
 * Version: 1.0.0
 *
 * Description:
 *   Network monitoring and analysis tool for ESP32-S3 with touch display.
 *   Connects to WiFi networks and displays network statistics including:
 *   - WiFi connection status and signal strength
 *   - Connected clients with hostname resolution
 *   - MAC vendor identification via IEEE OUI database
 *   - Internet connectivity status
 *   - IP address information
 *
 *   Hardware:
 *     - Guition ESP32 4848S040 board (ESP32-S3, 480x480 LCD, GT911 touch)
 *
 *   Features:
 *     - WiFi AP or STA mode with persistent credentials
 *     - LVGL-based touchscreen UI with 3-tier device identification
 *     - Binary search OUI database lookup (38,439 vendors)
 *     - Memory-efficient chunked merge sort algorithm
 *     - FreeRTOS tasks for UI and network monitoring
 *     - LittleFS for configuration persistence
 *
 * License:
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <https://www.gnu.org/licenses/>.
 *  1.0.1 fix to address occasional hanging and longer text on Client page
 */

#define APP_VERSION "1.0.1"


#include <Arduino.h>
#include "Guition_ESP32_4848S040.h"
#include <Arduino_GFX_Library.h>
#include "lvgl.h"
#include <RobotoBold.c>
#include <TAMC_GT911.h>
#include <esp_heap_caps.h>

#include <WiFi.h>
#include <WiFiAP.h>
#include <WiFiUdp.h>
#include <ESPmDNS.h>
#include <esp_wifi.h>
#include <lwip/etharp.h>
#include <lwip/netif.h>
#include <ESP32Ping.h>

#include <LittleFS.h>
#include <ArduinoOTA.h>
#include <SPI.h>
#include <SD.h>
#include <HTTPClient.h>
#include <vector>
#include <map>
#include <algorithm>

// Touch panel definitions
#define TOUCH_SDA TP_SDA
#define TOUCH_SCL TP_SCL
#define TOUCH_INT TP_INT
#define TOUCH_RST TP_RST
#define TOUCH_WIDTH TFT_WIDTH
#define TOUCH_HEIGHT TFT_HEIGHT

// Display initialization - copied from working NMEATouch20
Arduino_DataBus *sw_spi_bus = new Arduino_SWSPI(GFX_NOT_DEFINED /* DC pin */, TFT_CS /* CS pin of display*/, TFT_SCK /* Clock */, TFT_SDA /* MOSI */, GFX_NOT_DEFINED /* Data in */);

Arduino_ESP32RGBPanel *rgbpanel = new Arduino_ESP32RGBPanel(
    TFT_DE /* DE */, TFT_VS /* VSYNC */, TFT_HS /* HSYNC */, TFT_PCLK /* PCLK */,
    TFT_R0_DB13 /* R0 */, TFT_R1_DB14 /* R1 */, TFT_R2_DB15 /* R2 */, TFT_R3_DB16 /* R3 */, TFT_R4_DB17 /* R4 */,
    TFT_G0_DB6 /* G0 */, TFT_G1_DB7 /* G1 */, TFT_G2_DB8 /* G2 */, TFT_G3_DB9 /* G3 */, TFT_G4_DB10 /* G4 */, TFT_G5_DB11 /* G5 */,
    TFT_B0_DB1 /* B0 */, TFT_B1_DB2 /* B1 */, TFT_B2_DB3 /* B2 */, TFT_B3_DB4 /* B3 */, TFT_B4_DB5 /* B4 */,
    TFT_HSYNC_POLARITY, TFT_HSYNC_FRONT_PORCH, TFT_HSYNC_PULSE_WIDTH, TFT_HSYNC_BACK_PORCH,
    TFT_VSYNC_POLARITY, TFT_VSYNC_FRONT_PORCH, TFT_VSYNC_PULSE_WIDTH, TFT_VSYNC_BACK_PORCH,
    TFT_PCLK_ACTIVE_NEG, TFT_DATA_SPEED, TFT_USE_BIG_ENDIAN);

extern const uint8_t st7701_type9_init_operations[];
Arduino_RGB_Display *tft = new Arduino_RGB_Display(
    TFT_WIDTH, TFT_HEIGHT, rgbpanel, ROTATION, TFT_AUTO_FLUSH,
    sw_spi_bus /* Arduino Data bus */, GFX_NOT_DEFINED /* Reset pin, internal*/,
    st7701_type9_init_operations, sizeof(st7701_type9_init_operations));

// Global mutexes
SemaphoreHandle_t fs_mutex = NULL;
SemaphoreHandle_t lvgl_mutex = NULL;
SemaphoreHandle_t scan_mutex = NULL;  // Protects scanning operations
SemaphoreHandle_t devices_mutex = NULL;  // Protects networkDevices vector

// Configuration storage (8 parameters)
String configValues[8] = {"", "", "Network Analyser", "Epoxy123", "1", "30", "0", "0"};
const String configNames[8] = {" WiFi SSID", " WiFi Password", " AP SSID", " AP Password", " Active Probe", " Probe Interval", " Device Timeout", " Timezone Offset"};
const char configTypes[8] = {'T', 'T', 'T', 'T', 'B', 'I', 'I', 'I'};

// WiFi status variables
volatile bool wifiConnected = false;
String currentSSID = "";
String currentIP = "";
int8_t rssi = 0;
bool internetConnected = false;
String publicIP = "---";  // Public IP address from external service

// SD card support - matches NMEATouch20 pattern
volatile bool sdCardReady = false;  // Changed from sdCardAvailable to match NMEATouch20
const unsigned long OUI_UPDATE_INTERVAL = 30 * 24 * 60 * 60; // 30 days in seconds
SemaphoreHandle_t sdFileMutex = NULL;  // Changed from sd_mutex to match NMEATouch20

// Display objects
lv_obj_t *main_screen = nullptr;
lv_obj_t *status_label = nullptr;
lv_obj_t *wifi_label = nullptr;
lv_obj_t *ip_label = nullptr;
lv_obj_t *rssi_label = nullptr;
lv_obj_t *internet_label = nullptr;
lv_obj_t *public_ip_label = nullptr;  // Public IP address label
lv_obj_t *gateway_label = nullptr;
lv_obj_t *dns_label = nullptr;
lv_obj_t *device_list = nullptr;
lv_obj_t *scan_indicator = nullptr;
lv_display_t *display_object = nullptr;

// WiFi Setup Screen objects
lv_obj_t *wifi_setup_screen = nullptr;
lv_obj_t *network_list = nullptr;
lv_obj_t *password_screen = nullptr;
lv_obj_t *password_textarea = nullptr;
lv_obj_t *keyboard = nullptr;
lv_obj_t *connect_button = nullptr;
lv_obj_t *cancel_button = nullptr;
lv_obj_t *wifi_scan_indicator = nullptr;
lv_obj_t *splash_loading_indicator = nullptr;

// WiFi setup state
String selected_ssid = "";
volatile bool wifi_scanning = false;
QueueHandle_t wifi_scan_queue = NULL;
QueueHandle_t hostname_queue = NULL;  // Queue for hostname resolution requests

// Settings screen objects
lv_obj_t *settings_screen = nullptr;
lv_obj_t *settings_btn = nullptr;
lv_obj_t *settings_probe_switch = nullptr;
lv_obj_t *settings_interval_dropdown = nullptr;
lv_obj_t *settings_timeout_dropdown = nullptr;
lv_obj_t *settings_timezone_dropdown = nullptr;

// Device details screen objects
lv_obj_t *details_screen = nullptr;
lv_obj_t *details_content = nullptr;
lv_obj_t *details_port_scan_led = nullptr;  // LED for port scan button
lv_obj_t *details_ping_led = nullptr;  // LED for ping button
int selected_device_index = -1;

// Port scan and ping results
struct PortScanResult {
  uint16_t port;
  bool is_open;
  String service_name;
};
struct PingStats {
  int packets_sent = 0;
  int packets_received = 0;
  float min_ms = 0;
  float max_ms = 0;
  float avg_ms = 0;
};
std::vector<PortScanResult> current_port_scan;
PingStats current_ping_stats;
volatile bool port_scan_in_progress = false;
volatile bool ping_in_progress = false;
int scan_results_for_device = -1;  // Track which device index these results belong to
String port_scan_target_ip = "";
String ping_target_ip = "";
TaskHandle_t port_scan_task_handle = NULL;
TaskHandle_t ping_task_handle = NULL;
volatile bool need_details_refresh = false;

// Network scanner configuration (loaded from config.txt)
bool activeProbeEnabled = true;
int probeIntervalSeconds = 30;
int deviceTimeoutSeconds = 0;  // 0 = never timeout
int timezoneOffsetHours = 0;  // UTC offset in hours

// Time display
lv_obj_t *time_label = nullptr;

// OUI update dialog and progress
volatile bool ouiUpdateUserChoice = false;
volatile bool ouiUpdateDialogActive = false;
lv_obj_t* ouiProgressBar = nullptr;
lv_obj_t* ouiProgressLabel = nullptr;
lv_obj_t* ouiProgressScreen = nullptr;

// Scan control
volatile bool initialScanDone = false;
volatile bool deviceListChanged = false;
volatile bool scanInProgress = false;

// UI Constants
const lv_color_t COLOR_TITLE = lv_color_hex(0xFFFFFF);       // White for titles
const lv_color_t COLOR_ACCENT = lv_color_hex(0x00FFFF);      // Cyan for accents
const lv_color_t COLOR_SUCCESS = lv_color_hex(0x00FF00);     // Green
const lv_color_t COLOR_WARNING = lv_color_hex(0xFFFF00);     // Yellow
const lv_color_t COLOR_ERROR = lv_color_hex(0xFF0000);       // Red
const lv_color_t COLOR_TEXT = lv_color_hex(0xCCCCCC);        // Light gray
const lv_color_t COLOR_INDICATOR_ON = lv_color_hex(0x00FF00);  // Green LED
const lv_color_t COLOR_INDICATOR_OFF = lv_color_hex(0x404040); // Gray LED
const lv_color_t COLOR_BUTTON = lv_color_hex(0x1a1a1a);      // Darker gray for all buttons

const int INDICATOR_LED_X = 450;
const int INDICATOR_LED_Y = 12;
const int INDICATOR_LED_SIZE = 16;

const unsigned long NETWORK_TIMEOUT_MS = 300000;  // 5 minutes
const unsigned long CLIENT_SCAN_INTERVAL_MS = 3000;  // 3 seconds
const unsigned long WIFI_SCAN_INTERVAL_MS = 10000;   // 10 seconds
const unsigned long LED_BLINK_INTERVAL_MS = 500;     // 500ms

// OUI Database file paths
const char* OUI_DATABASE_FILE = "/OUI.txt";      // Main OUI database file
const char* OUI_INDEX_FILE = "/oui.idx";         // Index file for fast lookups
const char* OUI_TEMP_FILE = "/oui.tmp";          // Temporary file during download
const char* OUI_BACKUP_FILE = "/OUI.bak";        // Backup of previous database
const char* OUI_TIMESTAMP_FILE = "/oui_timestamp.txt";  // Last update timestamp
const char* OUI_PENDING_FILE = "/oui_pending.txt";      // Pending update flag

// Structure for network devices
struct NetworkDevice {
  String mac;
  String ip;
  String name;
  String vendor;           // Cached vendor name (looked up once)
  int rssi;
  unsigned long lastSeen;  // Timestamp when last detected
  bool hostnameResolved;   // Track if we've attempted hostname lookup
  bool fromDHCP;           // True if hostname came from DHCP snooping (authoritative)
  bool vendorFromSD;       // True if vendor came from SD card database (orange)
  bool vendorResolved;     // True if hardcoded vendor lookup has been attempted (green)
  bool vendorSDAttempted;  // True if SD database lookup has been attempted
};

// Structure for WiFi networks
struct WiFiNetwork {
  String ssid;
  int rssi;
  int channel;
  bool isOpen;
  wifi_auth_mode_t encryptionType;
  unsigned long lastSeen;
};

// Structure for hostname resolution request
struct HostnameRequest {
  char ip[16];   // e.g., "192.168.1.100" (max 15 chars + null)
  char mac[18];  // e.g., "AA:BB:CC:DD:EE:FF" (17 chars + null)
};

std::vector<NetworkDevice> networkDevices;
std::vector<WiFiNetwork> wifiNetworks;

// Forward declarations
String getMacVendor(const String& mac, bool* fromSD = nullptr);
String getMacVendorHardcoded(const String& mac);
String getMacVendorFromSD(const String& mac);
bool needsOUIUpdate();
void downloadOUIDatabase();
void updateIndexProgress(int entriesIndexed, int totalEntries);
void buildOUIIndex();
long binarySearchOUIIndex(const String& oui);
void showOUIUpdateDialog();
void handleOUIUpdateFlow();
void createOUIProgressScreen(const char* title_text = "Downloading Database");
void destroyOUIProgressScreen();
void createDeviceDetailsScreen(int device_index);
void destroyDeviceDetailsScreen();
void scanPortsForDevice(const String& ip);
void pingDevice(const String& ip);
String getServiceName(uint16_t port);
static void device_label_click_handler(lv_event_t *e);
static void details_back_btn_handler(lv_event_t *e);
void network_item_event_handler(lv_event_t *e);
void init_display_buffers(lv_display_t *disp);
void updateNetworkStats();

// Query public IP address from external service
String getPublicIP() {
  if (!internetConnected) return "---";
  
  WiFiClient client;
  const char* host = "api.ipify.org";  // Simple, fast, reliable service
  const int port = 80;
  
  Serial.println("[Public IP] Querying api.ipify.org...");
  
  if (!client.connect(host, port, 2000)) {  // 2 second timeout
    Serial.println("[Public IP] Connection failed");
    return "---";
  }
  
  // Send HTTP GET request
  client.print("GET / HTTP/1.1\r\n");
  client.print("Host: api.ipify.org\r\n");
  client.print("Connection: close\r\n\r\n");
  
  // Wait for response (max 2 seconds)
  unsigned long timeout = millis();
  while (client.connected() && !client.available()) {
    if (millis() - timeout > 2000) {
      Serial.println("[Public IP] Response timeout");
      client.stop();
      return "---";
    }
    delay(10);
  }
  
  // Read response
  String response = "";
  while (client.available()) {
    response += (char)client.read();
  }
  client.stop();
  
  // Parse response (format: "HTTP/1.1 200 OK\r\n...\r\n\r\nIP_ADDRESS")
  int bodyStart = response.indexOf("\r\n\r\n");
  if (bodyStart > 0) {
    String ip = response.substring(bodyStart + 4);
    ip.trim();
    
    // Validate IP format (basic check)
    if (ip.length() > 6 && ip.indexOf('.') > 0) {
      Serial.printf("[Public IP] Found: %s\n", ip.c_str());
      return ip;
    }
  }
  
  Serial.println("[Public IP] Parse failed");
  return "---";
}

void updateNetworkStats();
void initWiFi();
void createWiFiSetupUI();
void createNetworkStatsUI();
void create_settings_screen();
void DHCPSnoopTask(void *parameter);
void HostnameResolverTask(void *parameter);
void sdCardCheckTask(void *parameter);



// Create default factory config files if they don't exist
void createDefaultConfigFiles() {
  // Create config.txt with factory defaults
  if (!LittleFS.exists("/config.txt")) {
    Serial.println("[Config] config.txt not found, creating factory default...");
    File file = LittleFS.open("/config.txt", "w");
    if (file) {
      file.println("0:T WiFi SSID=");
      file.println("1:T WiFi Password=");
      file.println("2:T AP SSID=Network Analyser");
      file.println("3:T AP Password=Epoxy123");
      file.println("4:B Active Probe=1");
      file.println("5:I Probe Interval=30");
      file.println("6:I Device Timeout=0");
      file.println("7:I Timezone Offset=0");
      file.close();
      Serial.println("[Config] Factory default config.txt created");
    } else {
      Serial.println("[Config] ERROR: Failed to create config.txt");
    }
  }
  
  // Create config.bak with factory defaults (for factory reset)
  if (!LittleFS.exists("/config.bak")) {
    Serial.println("[Config] config.bak not found, creating factory default...");
    File file = LittleFS.open("/config.bak", "w");
    if (file) {
      file.println("0:T WiFi SSID=");
      file.println("1:T WiFi Password=");
      file.println("2:T AP SSID=Network Analyser");
      file.println("3:T AP Password=Epoxy123");
      file.println("4:B Active Probe=1");
      file.println("5:I Probe Interval=30");
      file.println("6:I Device Timeout=0");
      file.println("7:I Timezone Offset=0");
      file.close();
      Serial.println("[Config] Factory default config.bak created");
    } else {
      Serial.println("[Config] ERROR: Failed to create config.bak");
    }
  }
}

// Read config.txt file and populate configValues array
void readConfigFile() {
  // Ensure default files exist
  createDefaultConfigFiles();
  
  File file = LittleFS.open("/config.txt", "r");
  if (!file) {
    Serial.println("[Config] ERROR: Failed to open config.txt after creation attempt");
    return;
  }
  
  Serial.println("[Config] Reading config.txt...");
  while (file.available()) {
    String line = file.readStringUntil('\n');
    line.trim();
    
    if (line.length() == 0) continue;
    
    // Parse format: "index:type name=value"
    int colonPos = line.indexOf(':');
    if (colonPos < 0) continue;
    
    int index = line.substring(0, colonPos).toInt();
    if (index < 0 || index >= 8) continue;
    
    int equalsPos = line.indexOf('=', colonPos);
    if (equalsPos < 0) continue;
    
    String value = line.substring(equalsPos + 1);
    configValues[index] = value;
    
    Serial.printf("[Config] %d: %s = %s\n", index, configNames[index].c_str(), value.c_str());
  }
  file.close();
  Serial.println("[Config] Configuration loaded");
}

// Write configValues array to config.txt file
void saveConfigFile() {
  File file = LittleFS.open("/config.txt", "w");
  if (!file) {
    Serial.println("[Config] ERROR: Failed to open config.txt for writing");
    return;
  }
  
  Serial.println("[Config] Saving config.txt...");
  for (int i = 0; i < 8; i++) {
    String line = String(i) + ":" + configTypes[i] + configNames[i] + "=" + configValues[i];
    file.println(line);
    Serial.printf("[Config] Wrote: %s\n", line.c_str());
  }
  file.close();
  Serial.println("[Config] Configuration saved");
}

// Get config value by index
String getConfigValue(int index) {
  if (index >= 0 && index < 8) {
    return configValues[index];
  }
  return "";
}

// Set config value by index
void setConfigValue(int index, const String& value) {
  if (index >= 0 && index < 8) {
    configValues[index] = value;
  }
}

// ============================================================================

// Helper function to convert WiFi encryption type to readable string
String getSecurityType(wifi_auth_mode_t encType) {
  switch (encType) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    case WIFI_AUTH_WAPI_PSK: return "WAPI";
    default: return "Unknown";
  }
}

// Get color for WiFi channel - gradient from red (low) to green (middle) to blue (high)
// Uses dark colors for button backgrounds to maintain text readability
uint32_t getChannelColor(int channel) {
  // WiFi channels 1-14 (2.4 GHz band)
  // Channel 1-4: Dark red tones
  // Channel 5-10: Dark green tones
  // Channel 11-14: Dark blue tones
  
  if (channel < 1) channel = 1;
  if (channel > 14) channel = 14;
  
  // Normalize channel to 0.0-1.0 range (channel 1 = 0.0, channel 14 = 1.0)
  float t = (channel - 1) / 13.0;
  
  int r, g, b;
  
  if (t < 0.5) {
    // First half: Dark Red (60,0,0) -> Dark Green (0,60,0)
    float t2 = t * 2.0;  // Normalize to 0.0-1.0 for first half
    r = (int)(60 * (1.0 - t2));  // Red decreases
    g = (int)(60 * t2);           // Green increases
    b = 0;                        // No blue
  } else {
    // Second half: Dark Green (0,60,0) -> Dark Blue (0,0,60)
    float t2 = (t - 0.5) * 2.0;  // Normalize to 0.0-1.0 for second half
    r = 0;                        // No red
    g = (int)(60 * (1.0 - t2));  // Green decreases
    b = (int)(60 * t2);           // Blue increases
  }
  
  // Combine into hex color
  return (r << 16) | (g << 8) | b;
}

// Touch panel
TAMC_GT911 touch_panel = TAMC_GT911(TOUCH_SDA, TOUCH_SCL, TOUCH_INT, TOUCH_RST, TOUCH_WIDTH, TOUCH_HEIGHT);

// Display buffers
static uint8_t *draw_buf1 = nullptr;
static uint8_t *draw_buf2 = nullptr;
static const size_t draw_buf_size = TFT_WIDTH * 40 * sizeof(lv_color_t);

// Display flush callback
void my_disp_flush(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map)
{
  uint32_t w = lv_area_get_width(area);
  uint32_t h = lv_area_get_height(area);
  lv_draw_sw_rgb565_swap(px_map, w * h);
  tft->draw16bitBeRGBBitmap(area->x1, area->y1, (uint16_t *)px_map, w, h);
  lv_display_flush_ready(disp);
}

// Touch read callback
void my_touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data)
{
  touch_panel.read();
  if (touch_panel.isTouched)
  {
    data->point.x = touch_panel.points[0].x;
    data->point.y = touch_panel.points[0].y;
    data->state = LV_INDEV_STATE_PRESSED;
  }
  else
  {
    data->state = LV_INDEV_STATE_RELEASED;
  }
}

// Gesture event handlers for screen navigation
// Swipe navigation disabled - conflicts with scrolling and client selection
// Use navigation buttons instead (Networks/Clients/Back buttons)
/*
void wifi_setup_gesture_handler(lv_event_t *e)
{
  lv_event_code_t code = lv_event_get_code(e);
  if (code == LV_EVENT_GESTURE)
  {
    lv_dir_t dir = lv_indev_get_gesture_dir(lv_indev_get_act());
    if (dir == LV_DIR_LEFT && main_screen != nullptr)
    {
      // Swipe left: Go to Network Analyzer (Network Clients)
      Serial.println("[UI] Swipe left detected - switching to Network Analyzer");
      lv_scr_load(main_screen);
    }
    // Swipe right does nothing - this is the leftmost screen
  }
}
*/

// Swipe navigation disabled - conflicts with scrolling and client selection
// Use Settings button for navigation instead
/*
void network_analyzer_gesture_handler(lv_event_t *e)
{
  lv_event_code_t code = lv_event_get_code(e);
  if (code == LV_EVENT_GESTURE)
  {
    lv_dir_t dir = lv_indev_get_gesture_dir(lv_indev_get_act());
    if (dir == LV_DIR_RIGHT && wifi_setup_screen != nullptr)
    {
      // Swipe right: Go back to WiFi Setup (WiFi Networks)
      Serial.println("[UI] Swipe right detected - switching to WiFi Networks");
      lv_scr_load(wifi_setup_screen);
      
      // Trigger automatic scan when switching to WiFi Networks screen
      if (!wifi_scanning) {
        Serial.println("[WiFi Setup] Auto-triggering scan on screen switch...");
        uint8_t msg = 1;
        xQueueSend(wifi_scan_queue, &msg, 0);
      }
    }
    // Swipe left does nothing - this is the rightmost screen for now
  }
}
*/

// WiFi Setup - Network selection handler
void network_item_event_handler(lv_event_t *e)
{
  lv_event_code_t code = lv_event_get_code(e);
  if (code == LV_EVENT_CLICKED)
  {
    lv_obj_t *btn = (lv_obj_t *)lv_event_get_target(e);
    lv_obj_t *label = lv_obj_get_child(btn, 0);
    const char *text = lv_label_get_text(label);
    
    // Extract SSID from the label (format: "SSID (signal strength)")
    String full_text = String(text);
    int paren_pos = full_text.indexOf('(');
    if (paren_pos > 0) {
      selected_ssid = full_text.substring(0, paren_pos - 1);
      selected_ssid.trim();
      Serial.printf("[WiFi Setup] Selected network: %s\n", selected_ssid.c_str());
      
      // Show password entry screen - NO MUTEX, we're already in LVGL task!
      lv_scr_load(password_screen);
      lv_textarea_set_text(password_textarea, "");
      
      // Update SSID label on password screen
      lv_obj_t *ssid_label = lv_obj_get_child(password_screen, 0);  // First child is SSID label
      String ssid_text = "Network: " + selected_ssid;
      lv_label_set_text(ssid_label, ssid_text.c_str());
    }
  }
}

// WiFi Setup - Scan button handler
void scan_wifi_event_handler(lv_event_t *e)
{
  lv_event_code_t code = lv_event_get_code(e);
  if (code == LV_EVENT_CLICKED)
  {
    if (!wifi_scanning) {
      Serial.println("[WiFi Setup] Scan button pressed - sending queue message");
      uint8_t msg = 1;  // Message content doesn't matter, just a trigger
      xQueueSend(wifi_scan_queue, &msg, 0);  // Non-blocking send
    }
  }
}

// WiFi Setup - Connect button handler
void connect_wifi_event_handler(lv_event_t *e)
{
  lv_event_code_t code = lv_event_get_code(e);
  if (code == LV_EVENT_CLICKED)
  {
    const char *password = lv_textarea_get_text(password_textarea);
    Serial.printf("[WiFi Setup] Connecting to %s\n", selected_ssid.c_str());
    
    // Update config file and save to flash
    if (xSemaphoreTake(fs_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
      setConfigValue(0, selected_ssid);
      setConfigValue(1, String(password));
      saveConfigFile();
      xSemaphoreGive(fs_mutex);
      Serial.println("[WiFi Setup] Config saved to flash");
    } else {
      Serial.println("[WiFi Setup] ERROR: Failed to acquire FS mutex - config NOT saved");
    }
    
    // Restart to apply new settings
    Serial.println("[WiFi Setup] Restarting to apply new WiFi settings...");
    delay(1000);
    ESP.restart();
  }
}

// WiFi Setup - Cancel button handler
void cancel_wifi_event_handler(lv_event_t *e)
{
  lv_event_code_t code = lv_event_get_code(e);
  if (code == LV_EVENT_CLICKED)
  {
    Serial.println("[WiFi Setup] Cancelled password entry");
    // NO MUTEX - event handlers already run with mutex held!
    lv_scr_load(wifi_setup_screen);
  }
}

// Initialize display buffers
void init_display_buffers(lv_display_t *disp)
{
  draw_buf1 = (uint8_t *)heap_caps_malloc(draw_buf_size, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
  draw_buf2 = (uint8_t *)heap_caps_malloc(draw_buf_size, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
  
  if (!draw_buf1 || !draw_buf2)
  {
    Serial.println("[ERROR] Failed to allocate display buffers!");
    return;
  }
  
  lv_display_set_buffers(disp, draw_buf1, draw_buf2, draw_buf_size, LV_DISPLAY_RENDER_MODE_PARTIAL);
}

// Get number of connected clients (AP mode only)
int getConnectedClients()
{
  if (WiFi.getMode() != WIFI_AP && WiFi.getMode() != WIFI_AP_STA)
    return 0;
  
  wifi_sta_list_t stationList;
  esp_wifi_ap_get_sta_list(&stationList);
  return stationList.num;
}

// Create Splash Screen
void createSplashScreen(const char* status_text)
{
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
    Serial.println("[UI] Failed to acquire mutex for splash screen");
    return;
  }
  
  lv_obj_t *splash = lv_obj_create(NULL);
  lv_obj_set_style_bg_color(splash, lv_color_hex(0x000000), 0);
  
  // App title
  lv_obj_t *title = lv_label_create(splash);
  lv_label_set_text(title, "Network Analyzer");
  lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
  lv_obj_set_style_text_color(title, COLOR_TITLE, 0);
  lv_obj_align(title, LV_ALIGN_CENTER, 0, -80);
  
  // Author name
  lv_obj_t *author = lv_label_create(splash);
  lv_label_set_text(author, "Carl Schofield");
  lv_obj_set_style_text_font(author, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_color(author, COLOR_ACCENT, 0);
  lv_obj_align(author, LV_ALIGN_CENTER, 0, -45);
  
  // Version
  lv_obj_t *version = lv_label_create(splash);
  lv_label_set_text(version, "Version " APP_VERSION);
  lv_obj_set_style_text_font(version, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_color(version, lv_color_hex(0x808080), 0);
  lv_obj_align(version, LV_ALIGN_CENTER, 0, -10);
  
  // Status message
  lv_obj_t *status = lv_label_create(splash);
  lv_label_set_text(status, status_text);
  lv_obj_set_style_text_font(status, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_color(status, COLOR_WARNING, 0);
  lv_obj_align(status, LV_ALIGN_CENTER, 0, 40);
  
  // Loading indicator (blinking LED)
  splash_loading_indicator = lv_obj_create(splash);
  lv_obj_set_size(splash_loading_indicator, 20, 20);
  lv_obj_align(splash_loading_indicator, LV_ALIGN_CENTER, 0, 100);
  lv_obj_set_style_radius(splash_loading_indicator, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(splash_loading_indicator, COLOR_INDICATOR_ON, 0);
  lv_obj_set_style_border_width(splash_loading_indicator, 0, 0);
  
  lv_scr_load(splash);
  xSemaphoreGive(lvgl_mutex);
  
  // Turn on backlight AFTER screen is created
  digitalWrite(TFT_BL, HIGH);
}

// Create WiFi Setup Screen (shown in AP mode)
void createWiFiSetupUI()
{
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
    Serial.println("[UI] Failed to acquire mutex for WiFi setup UI");
    return;
  }
  
  // Main setup screen
  wifi_setup_screen = lv_obj_create(NULL);
  lv_obj_set_style_bg_color(wifi_setup_screen, lv_color_hex(0x000000), 0);
  
  // Clients button for navigation
  lv_obj_t *clients_btn = lv_btn_create(wifi_setup_screen);
  lv_obj_set_size(clients_btn, 80, 40);
  lv_obj_align(clients_btn, LV_ALIGN_TOP_LEFT, 10, 2);
  lv_obj_set_style_bg_color(clients_btn, COLOR_BUTTON, 0);
  lv_obj_set_style_shadow_width(clients_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(clients_btn, 0, 0);  // No border
  lv_obj_set_style_radius(clients_btn, 10, 0);  // Rounded corners
  lv_obj_t *clients_label = lv_label_create(clients_btn);
  lv_label_set_text(clients_label, "Clients");
  lv_obj_center(clients_label);
  lv_obj_add_event_cb(clients_btn, [](lv_event_t *e) {
    if (main_screen) {
      lv_scr_load(main_screen);
    }
  }, LV_EVENT_CLICKED, NULL);
  
  // Title
  lv_obj_t *title = lv_label_create(wifi_setup_screen);
  lv_label_set_text(title, "WiFi Networks");
  lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
  lv_obj_set_style_text_color(title, COLOR_TITLE, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 15);
  
  // Scanning indicator dot (circle)
  wifi_scan_indicator = lv_obj_create(wifi_setup_screen);
  lv_obj_set_size(wifi_scan_indicator, INDICATOR_LED_SIZE, INDICATOR_LED_SIZE);
  lv_obj_set_pos(wifi_scan_indicator, INDICATOR_LED_X, INDICATOR_LED_Y);
  lv_obj_set_style_radius(wifi_scan_indicator, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(wifi_scan_indicator, COLOR_INDICATOR_OFF, 0);
  lv_obj_set_style_border_width(wifi_scan_indicator, 0, 0);
  
  // Settings button (gear icon) - square, same height as Clients button
  lv_obj_t *wifi_settings_btn = lv_btn_create(wifi_setup_screen);
  lv_obj_set_size(wifi_settings_btn, 40, 40);
  lv_obj_set_pos(wifi_settings_btn, INDICATOR_LED_X - 50, INDICATOR_LED_Y - 12);
  lv_obj_set_style_bg_color(wifi_settings_btn, lv_color_hex(0x333333), 0);
  lv_obj_set_style_shadow_width(wifi_settings_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(wifi_settings_btn, 0, 0);  // No border
  lv_obj_t *wifi_settings_label = lv_label_create(wifi_settings_btn);
  lv_label_set_text(wifi_settings_label, LV_SYMBOL_SETTINGS);
  lv_obj_set_style_text_font(wifi_settings_label, &lv_font_montserrat_16, 0);
  lv_obj_center(wifi_settings_label);
  lv_obj_add_event_cb(wifi_settings_btn, [](lv_event_t *e) {
    if (settings_screen) {
      lv_scr_load(settings_screen);
    }
  }, LV_EVENT_CLICKED, NULL);
  
  // Network list container - expanded to fill screen
  network_list = lv_obj_create(wifi_setup_screen);
  lv_obj_set_size(network_list, 460, 420);
  lv_obj_set_pos(network_list, 10, 50);
  lv_obj_set_style_bg_opa(network_list, LV_OPA_TRANSP, 0);  // Transparent
  lv_obj_set_style_border_width(network_list, 0, 0);
  lv_obj_set_style_radius(network_list, 0, 0);
  lv_obj_set_scrollbar_mode(network_list, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_set_scroll_dir(network_list, LV_DIR_VER);  // Only vertical scrolling
  lv_obj_set_flex_flow(network_list, LV_FLEX_FLOW_COLUMN);
  
  // Swipe navigation removed - use Clients button instead (consistent with other screens)
  
  // Initial message
  lv_obj_t *initial_msg = lv_label_create(network_list);
  lv_label_set_text(initial_msg, "Scanning for networks...");
  lv_obj_set_style_text_color(initial_msg, lv_color_hex(0xFFFF00), 0);
  lv_obj_set_style_text_font(initial_msg, &lv_font_montserrat_14, 0);
  
  // Password entry screen
  password_screen = lv_obj_create(NULL);
  lv_obj_set_style_bg_color(password_screen, lv_color_hex(0x000000), 0);
  lv_obj_set_scrollbar_mode(password_screen, LV_SCROLLBAR_MODE_OFF);  // No scrolling
  
  // SSID label (will be updated when network is selected)
  lv_obj_t *ssid_label = lv_label_create(password_screen);
  lv_label_set_text(ssid_label, "Network: ");
  lv_obj_set_style_text_font(ssid_label, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_color(ssid_label, lv_color_hex(0x00FFFF), 0);
  lv_obj_set_pos(ssid_label, 10, 10);
  
  // Password label and text area on same line
  lv_obj_t *pwd_label = lv_label_create(password_screen);
  lv_label_set_text(pwd_label, "Password:");
  lv_obj_set_style_text_font(pwd_label, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_color(pwd_label, lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_pos(pwd_label, 10, 45);
  
  password_textarea = lv_textarea_create(password_screen);
  lv_obj_set_size(password_textarea, 350, 40);
  lv_obj_set_pos(password_textarea, 120, 40);
  lv_textarea_set_placeholder_text(password_textarea, "Enter password...");
  lv_obj_set_style_text_font(password_textarea, &lv_font_montserrat_16, 0);
  lv_textarea_set_password_mode(password_textarea, true);
  lv_textarea_set_one_line(password_textarea, true);
  
  // Connect and Cancel buttons (above keyboard)
  connect_button = lv_btn_create(password_screen);
  lv_obj_set_size(connect_button, 200, 45);
  lv_obj_set_pos(connect_button, 20, 95);
  lv_obj_set_style_bg_color(connect_button, lv_color_hex(0x00AA00), 0);
  lv_obj_set_style_shadow_width(connect_button, 0, 0);  // No shadow
  lv_obj_set_style_border_width(connect_button, 0, 0);  // No border
  lv_obj_add_event_cb(connect_button, connect_wifi_event_handler, LV_EVENT_CLICKED, NULL);
  
  lv_obj_t *connect_label = lv_label_create(connect_button);
  lv_label_set_text(connect_label, "Connect");
  lv_obj_set_style_text_font(connect_label, &lv_font_montserrat_18, 0);
  lv_obj_center(connect_label);
  
  cancel_button = lv_btn_create(password_screen);
  lv_obj_set_size(cancel_button, 200, 45);
  lv_obj_set_pos(cancel_button, 260, 95);
  lv_obj_set_style_bg_color(cancel_button, lv_color_hex(0xAA0000), 0);
  lv_obj_set_style_shadow_width(cancel_button, 0, 0);  // No shadow
  lv_obj_set_style_border_width(cancel_button, 0, 0);  // No border
  lv_obj_add_event_cb(cancel_button, cancel_wifi_event_handler, LV_EVENT_CLICKED, NULL);
  
  lv_obj_t *cancel_label = lv_label_create(cancel_button);
  lv_label_set_text(cancel_label, "Cancel");
  lv_obj_set_style_text_font(cancel_label, &lv_font_montserrat_18, 0);
  lv_obj_center(cancel_label);
  
  // Keyboard - moved up 150 pixels from original y=150 position
  keyboard = lv_keyboard_create(password_screen);
  lv_obj_set_size(keyboard, 480, 330);
  lv_obj_set_pos(keyboard, 0, 0);  // Original was 150, moved to top (150 pixels up)
  lv_keyboard_set_textarea(keyboard, password_textarea);
  lv_keyboard_set_mode(keyboard, LV_KEYBOARD_MODE_TEXT_LOWER);  // Start with lowercase
  
  xSemaphoreGive(lvgl_mutex);
  
  Serial.println("[WiFi Setup] Setup UI created");
}

// Create the network stats UI
void createNetworkStatsUI()
{
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
    Serial.println("[UI] Failed to acquire mutex for Network Stats UI");
    return;
  }
  
  main_screen = lv_obj_create(NULL);
  lv_obj_set_style_bg_color(main_screen, lv_color_hex(0x000000), 0);
  
  // Networks button for navigation
  lv_obj_t *networks_btn = lv_btn_create(main_screen);
  lv_obj_set_size(networks_btn, 80, 40);
  lv_obj_align(networks_btn, LV_ALIGN_TOP_LEFT, 10, 2);
  lv_obj_set_style_bg_color(networks_btn, COLOR_BUTTON, 0);
  lv_obj_set_style_shadow_width(networks_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(networks_btn, 0, 0);  // No border
  lv_obj_set_style_radius(networks_btn, 10, 0);  // Rounded corners
  lv_obj_t *networks_label = lv_label_create(networks_btn);
  lv_label_set_text(networks_label, "Networks");
  lv_obj_center(networks_label);
  lv_obj_add_event_cb(networks_btn, [](lv_event_t *e) {
    if (wifi_setup_screen) {
      lv_scr_load(wifi_setup_screen);
    }
  }, LV_EVENT_CLICKED, NULL);
  
  // Title
  lv_obj_t *title = lv_label_create(main_screen);
  lv_label_set_text(title, "Network Clients");
  lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
  lv_obj_set_style_text_color(title, COLOR_TITLE, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 15);
  
  // Scanning indicator dot (circle) - top right
  scan_indicator = lv_obj_create(main_screen);
  lv_obj_set_size(scan_indicator, INDICATOR_LED_SIZE, INDICATOR_LED_SIZE);
  lv_obj_set_pos(scan_indicator, INDICATOR_LED_X, INDICATOR_LED_Y);
  lv_obj_set_style_radius(scan_indicator, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(scan_indicator, COLOR_INDICATOR_OFF, 0);
  lv_obj_set_style_border_width(scan_indicator, 0, 0);
  
  // Settings button (gear icon) - square, same height as Networks button
  settings_btn = lv_btn_create(main_screen);
  lv_obj_set_size(settings_btn, 40, 40);
  lv_obj_set_pos(settings_btn, INDICATOR_LED_X - 50, INDICATOR_LED_Y - 12);
  lv_obj_set_style_bg_color(settings_btn, lv_color_hex(0x333333), 0);
  lv_obj_set_style_shadow_width(settings_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(settings_btn, 0, 0);  // No border
  lv_obj_t *settings_label = lv_label_create(settings_btn);
  lv_label_set_text(settings_label, LV_SYMBOL_SETTINGS);
  lv_obj_set_style_text_font(settings_label, &lv_font_montserrat_16, 0);
  lv_obj_center(settings_label);
  lv_obj_add_event_cb(settings_btn, [](lv_event_t *e) {
    if (settings_screen) {
      lv_scr_load(settings_screen);
    }
  }, LV_EVENT_CLICKED, NULL);
  
  int y_offset = 50;  // Moved down 15px
  int line_height = 22;
  
  // WiFi Status - more compact
  wifi_label = lv_label_create(main_screen);
  lv_label_set_text(wifi_label, "WiFi: Disconnected");
  lv_obj_set_style_text_font(wifi_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(wifi_label, lv_color_hex(0xFF0000), 0);
  lv_obj_align(wifi_label, LV_ALIGN_TOP_LEFT, 10, y_offset);
  y_offset += line_height;
  
  // Line 1: IP, Signal Strength, and MAC Address
  ip_label = lv_label_create(main_screen);
  lv_label_set_text(ip_label, "IP: ---");
  lv_obj_set_style_text_font(ip_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(ip_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_align(ip_label, LV_ALIGN_TOP_LEFT, 10, y_offset);
  
  rssi_label = lv_label_create(main_screen);
  lv_label_set_text(rssi_label, "RSSI: ---");
  lv_obj_set_style_text_font(rssi_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(rssi_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_align(rssi_label, LV_ALIGN_TOP_LEFT, 155, y_offset);
  
  status_label = lv_label_create(main_screen);
  lv_label_set_text(status_label, "MAC: ---");
  lv_obj_set_style_text_font(status_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(status_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_align(status_label, LV_ALIGN_TOP_LEFT, 280, y_offset);
  y_offset += line_height;
  
  // Line 2: Internet Status, Gateway, and DNS
  internet_label = lv_label_create(main_screen);
  lv_label_set_text(internet_label, "Net: Unknown");
  lv_obj_set_style_text_font(internet_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(internet_label, lv_color_hex(0xFFFF00), 0);
  lv_obj_align(internet_label, LV_ALIGN_TOP_LEFT, 10, y_offset);
  
  gateway_label = lv_label_create(main_screen);
  lv_label_set_text(gateway_label, "GW: ---");
  lv_obj_set_style_text_font(gateway_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(gateway_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_align(gateway_label, LV_ALIGN_TOP_LEFT, 165, y_offset);
  
  dns_label = lv_label_create(main_screen);
  lv_label_set_text(dns_label, "DNS: ---");
  lv_obj_set_style_text_font(dns_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(dns_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_align(dns_label, LV_ALIGN_TOP_LEFT, 290, y_offset);
  
  // Time/Date aligned with WiFi status line (right side)
  time_label = lv_label_create(main_screen);
  lv_label_set_text(time_label, "--:--:--");
  lv_obj_set_style_text_font(time_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(time_label, lv_color_hex(0x00FFFF), 0);
  lv_obj_align(time_label, LV_ALIGN_TOP_RIGHT, -10, 50);  // Aligned with first WiFi line
  
  y_offset += line_height;
  
  // Line 3: Public IP (shown when internet connected)
  public_ip_label = lv_label_create(main_screen);
  lv_label_set_text(public_ip_label, "Public IP: ---");
  lv_obj_set_style_text_font(public_ip_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(public_ip_label, lv_color_hex(0x00FFFF), 0);
  lv_obj_align(public_ip_label, LV_ALIGN_TOP_LEFT, 10, y_offset);
  
  y_offset += line_height + 5;
  
  // Scrollable device list container - holds individual labels for each device
  device_list = lv_obj_create(main_screen);
  lv_obj_set_size(device_list, 460, 297);  // Reduced height by 22px for public IP line
  lv_obj_set_pos(device_list, 10, y_offset);
  lv_obj_set_style_bg_opa(device_list, LV_OPA_TRANSP, 0);  // Transparent
  lv_obj_set_style_border_width(device_list, 0, 0);
  lv_obj_set_style_radius(device_list, 0, 0);
  lv_obj_set_style_pad_all(device_list, 5, 0);
  lv_obj_set_flex_flow(device_list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(device_list, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
  lv_obj_set_scrollbar_mode(device_list, LV_SCROLLBAR_MODE_AUTO);
  
  // Initial loading message
  lv_obj_t *loading_label = lv_label_create(device_list);
  lv_label_set_text(loading_label, "Scanning network...");
  lv_obj_set_style_text_font(loading_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(loading_label, lv_color_hex(0x00FF00), 0);
  
  // Swipe navigation removed - use Settings button instead (gesture conflicts with client selection)
  
  xSemaphoreGive(lvgl_mutex);
}

// Settings screen event handlers
static void settings_save_handler(lv_event_t *e) {
  // Get values from UI controls
  bool newProbeEnabled = lv_obj_has_state(settings_probe_switch, LV_STATE_CHECKED);
  
  uint16_t intervalIdx = lv_dropdown_get_selected(settings_interval_dropdown);
  int newInterval = 30;  // Default
  switch(intervalIdx) {
    case 0: newInterval = 5; break;
    case 1: newInterval = 10; break;
    case 2: newInterval = 30; break;
    case 3: newInterval = 60; break;
  }
  
  uint16_t timeoutIdx = lv_dropdown_get_selected(settings_timeout_dropdown);
  int newTimeout = 0;  // Default = never
  switch(timeoutIdx) {
    case 0: newTimeout = 0; break;      // Never
    case 1: newTimeout = 300; break;    // 5 min
    case 2: newTimeout = 1800; break;   // 30 min
    case 3: newTimeout = 3600; break;   // 1 hour
    case 4: newTimeout = 21600; break;  // 6 hours
  }
  
  uint16_t timezoneIdx = lv_dropdown_get_selected(settings_timezone_dropdown);
  int newTimezone = timezoneIdx - 12;  // Convert index to UTC offset (-12 to +12)
  
  Serial.printf("[Settings] Saving: Probe=%s, Interval=%ds, Timeout=%ds, Timezone=UTC%+d\n",
                newProbeEnabled ? "ON" : "OFF", newInterval, newTimeout, newTimezone);
  
  // Update config file
  setConfigValue(4, newProbeEnabled ? "1" : "0");
  setConfigValue(5, String(newInterval));
  setConfigValue(6, String(newTimeout));
  setConfigValue(7, String(newTimezone));
  saveConfigFile();  // Write changes to config.txt
  
  // Apply settings immediately
  activeProbeEnabled = newProbeEnabled;
  probeIntervalSeconds = newInterval;
  deviceTimeoutSeconds = newTimeout;
  timezoneOffsetHours = newTimezone;
  
  // Reconfigure NTP with new timezone
  configTime(timezoneOffsetHours * 3600, 0, "pool.ntp.org", "time.nist.gov");
  
  Serial.println("[Settings] Settings saved and applied");
  
  // Return to main screen
  if (main_screen) {
    lv_scr_load(main_screen);
  }
}

static void settings_cancel_handler(lv_event_t *e) {
  // Discard changes and return to main screen
  Serial.println("[Settings] Cancel clicked");
  if (main_screen) {
    lv_scr_load(main_screen);
  }
}

static void settings_change_wifi_handler(lv_event_t *e) {
  Serial.println("[Settings] Change WiFi clicked");
  // Switch to WiFi setup screen to select new network
  if (wifi_setup_screen) {
    lv_scr_load(wifi_setup_screen);
  }
}

static void factory_reset_confirm_handler(lv_event_t *e) {
  Serial.println("[Settings] Factory reset confirmed");
  
  // Copy config.bak to config.txt
  if (xSemaphoreTake(fs_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
    File bakFile = LittleFS.open("/config.bak", "r");
    File cfgFile = LittleFS.open("/config.txt", "w");
    
    if (bakFile && cfgFile) {
      while (bakFile.available()) {
        cfgFile.write(bakFile.read());
      }
      bakFile.close();
      cfgFile.close();
      Serial.println("[Settings] Factory reset complete - config.txt restored from config.bak");
      
      // Reload config
      readConfigFile();
      
      // Update runtime variables
      activeProbeEnabled = true;
      probeIntervalSeconds = 30;
      deviceTimeoutSeconds = 0;
      timezoneOffsetHours = 0;
      
      // Reconfigure NTP
      configTime(0, 0, "pool.ntp.org", "time.nist.gov");
      
      Serial.println("[Settings] Please restart device for WiFi changes to take effect");
    } else {
      Serial.println("[Settings] ERROR: Failed to open config files");
    }
    xSemaphoreGive(fs_mutex);
  }
  
  // Close message box
  lv_obj_t *target = (lv_obj_t*)lv_event_get_target(e);
  lv_obj_t *mbox = (lv_obj_t*)lv_obj_get_parent(lv_obj_get_parent(target));
  lv_msgbox_close(mbox);
  
  // Return to main screen
  if (main_screen) {
    lv_scr_load(main_screen);
  }
}

// Confirmation handler for OUI update - actually performs the update
static void settings_oui_confirm_handler(lv_event_t *e) {
  lv_obj_t *btn = static_cast<lv_obj_t*>(lv_event_get_target(e));
  lv_msgbox_close(lv_obj_get_parent(btn));
  
  Serial.println("[Settings] OUI update confirmed - setting flag and rebooting");
  
  // Create pending flag file to trigger update on next boot
  if (sdCardReady && sdFileMutex) {
    if (xSemaphoreTake(sdFileMutex, pdMS_TO_TICKS(2000)) == pdTRUE) {
      File flagFile = SD.open(OUI_PENDING_FILE, FILE_WRITE);
      if (flagFile) {
        flagFile.println("1");
        flagFile.flush();  // Ensure it's written before reboot
        flagFile.close();
        Serial.println("[OUI Update] Pending flag created");
      }
      xSemaphoreGive(sdFileMutex);
    }
  }
  
  // Show message and reboot
  lv_obj_t *mbox = lv_msgbox_create(NULL);
  lv_msgbox_add_title(mbox, "OUI Database Update");
  lv_msgbox_add_text(mbox, "Device will reboot and update\\nthe OUI database on startup.\\n\\nThis may take 1-2 minutes.");
  lv_obj_t *ok_btn = lv_msgbox_add_footer_button(mbox, "OK");
  
  // Reboot after short delay
  vTaskDelay(pdMS_TO_TICKS(2000));
  ESP.restart();
}

// OUI Database update handler - shows confirmation dialog
static void settings_oui_update_handler(lv_event_t *e) {
  Serial.println("[Settings] OUI update button clicked - showing confirmation");
  
  // Show confirmation dialog
  lv_obj_t *mbox = lv_msgbox_create(NULL);
  lv_msgbox_add_title(mbox, "Update OUI Database?");
  lv_msgbox_add_text(mbox, "Download 6MB vendor database?\\n\\nDevice will reboot and update.\\nThis takes about 1-2 minutes.");
  lv_msgbox_add_close_button(mbox);
  
  lv_obj_t *btn_confirm = lv_msgbox_add_footer_button(mbox, "Update & Reboot");
  lv_obj_t *btn_cancel = lv_msgbox_add_footer_button(mbox, "Cancel");
  
  lv_obj_add_event_cb(btn_confirm, settings_oui_confirm_handler, LV_EVENT_CLICKED, NULL);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    lv_obj_t *btn = static_cast<lv_obj_t*>(lv_event_get_target(e));
    lv_msgbox_close(lv_obj_get_parent(btn));
  }, LV_EVENT_CLICKED, NULL);
}

static void settings_factory_reset_handler(lv_event_t *e) {
  Serial.println("[Settings] Factory reset button clicked");
  
  // Show confirmation dialog
  lv_obj_t *mbox = lv_msgbox_create(NULL);
  lv_msgbox_add_title(mbox, "Factory Reset");
  lv_msgbox_add_text(mbox, "Reset all settings to defaults?\\nThis will clear WiFi credentials!");
  lv_msgbox_add_close_button(mbox);
  
  lv_obj_t *btn = lv_msgbox_add_footer_button(mbox, "Reset");
  lv_obj_set_style_bg_color(btn, lv_color_hex(0xFF0000), 0);
  lv_obj_add_event_cb(btn, factory_reset_confirm_handler, LV_EVENT_CLICKED, NULL);
}

// Create settings screen
void create_settings_screen() {
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
    Serial.println("[UI] Failed to acquire mutex for Settings UI");
    return;
  }
  
  settings_screen = lv_obj_create(NULL);
  lv_obj_set_style_bg_color(settings_screen, lv_color_hex(0x000000), 0);
  
  // Title
  lv_obj_t *title = lv_label_create(settings_screen);
  lv_label_set_text(title, LV_SYMBOL_SETTINGS " Settings");
  lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
  lv_obj_set_style_text_color(title, lv_color_hex(0x00FF00), 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);
  
  int y = 60;
  int line_h = 35;
  
  // Network Scanner Section title (LEFT) and SSID display (RIGHT) on same line
  lv_obj_t *scanner_title = lv_label_create(settings_screen);
  lv_label_set_text(scanner_title, "Network Scanner");
  lv_obj_set_style_text_font(scanner_title, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_color(scanner_title, lv_color_hex(0xFFFF00), 0);
  lv_obj_align(scanner_title, LV_ALIGN_TOP_LEFT, 20, y);
  
  // Current SSID display on right side - Green and larger font
  lv_obj_t *ssid_label = lv_label_create(settings_screen);
  String ssid_text = "SSID: " + getConfigValue(0);
  if (ssid_text.length() > 23) ssid_text = ssid_text.substring(0, 20) + "...";
  lv_label_set_text(ssid_label, ssid_text.c_str());
  lv_obj_set_style_text_font(ssid_label, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_color(ssid_label, lv_color_hex(0x00FF00), 0);
  lv_obj_align(ssid_label, LV_ALIGN_TOP_RIGHT, -15, y);
  y += 30;
  
  // Current subnet info (read-only)
  lv_obj_t *subnet_label = lv_label_create(settings_screen);
  IPAddress subnet = WiFi.localIP();
  IPAddress mask = WiFi.subnetMask();
  String subnet_text = "Subnet: " + subnet.toString() + " / " + String(mask[0]) + "." + String(mask[1]) + "." + String(mask[2]) + "." + String(mask[3]) + " (auto)";
  lv_label_set_text(subnet_label, subnet_text.c_str());
  lv_obj_set_style_text_font(subnet_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(subnet_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_set_pos(subnet_label, 20, y);
  y += 30;
  
  // Probe Interval dropdown (LEFT) and Active Probing switch (RIGHT) on same line
  lv_obj_t *interval_label = lv_label_create(settings_screen);
  lv_label_set_text(interval_label, "Probe Interval:");
  lv_obj_set_style_text_font(interval_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(interval_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_set_pos(interval_label, 20, y);
  
  settings_interval_dropdown = lv_dropdown_create(settings_screen);
  lv_dropdown_set_options(settings_interval_dropdown, "5s\n10s\n30s\n60s");
  lv_obj_set_pos(settings_interval_dropdown, 140, y - 5);
  lv_obj_set_width(settings_interval_dropdown, 100);  // Same width as timeout dropdown
  // Set current value
  if (probeIntervalSeconds <= 5) lv_dropdown_set_selected(settings_interval_dropdown, 0);
  else if (probeIntervalSeconds <= 10) lv_dropdown_set_selected(settings_interval_dropdown, 1);
  else if (probeIntervalSeconds <= 30) lv_dropdown_set_selected(settings_interval_dropdown, 2);
  else lv_dropdown_set_selected(settings_interval_dropdown, 3);
  
  // Active Probing on right side - aligned with right buttons
  lv_obj_t *probe_label = lv_label_create(settings_screen);
  lv_label_set_text(probe_label, "Active Probe:");
  lv_obj_set_style_text_font(probe_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(probe_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_align(probe_label, LV_ALIGN_TOP_RIGHT, -110, y);
  
  settings_probe_switch = lv_switch_create(settings_screen);
  lv_obj_align(settings_probe_switch, LV_ALIGN_TOP_RIGHT, -15, y - 5);
  if (activeProbeEnabled) {
    lv_obj_add_state(settings_probe_switch, LV_STATE_CHECKED);
  }
  y += line_h + 15;  // Extra spacing before OUI button
  
  // Update OUI DB button (RIGHT side, 15px from edge)
  lv_obj_t *oui_update_btn = lv_btn_create(settings_screen);
  lv_obj_set_size(oui_update_btn, 200, 40);
  lv_obj_align(oui_update_btn, LV_ALIGN_TOP_RIGHT, -15, y);
  lv_obj_set_style_bg_color(oui_update_btn, lv_color_hex(0x2C7A7B), 0); // Teal
  lv_obj_set_style_shadow_width(oui_update_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(oui_update_btn, 0, 0);  // No border
  lv_obj_t *oui_label = lv_label_create(oui_update_btn);
  lv_label_set_text(oui_label, LV_SYMBOL_DOWNLOAD " Update OUI DB");
  lv_obj_center(oui_label);
  lv_obj_add_event_cb(oui_update_btn, settings_oui_update_handler, LV_EVENT_CLICKED, NULL);
  
  // Device Timeout dropdown (LEFT side)
  lv_obj_t *timeout_label = lv_label_create(settings_screen);
  lv_label_set_text(timeout_label, "Device Timeout:");
  lv_obj_set_style_text_font(timeout_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(timeout_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_set_pos(timeout_label, 20, y);
  
  settings_timeout_dropdown = lv_dropdown_create(settings_screen);
  lv_dropdown_set_options(settings_timeout_dropdown, "Never\n5 min\n30 min\n1 hour\n6 hours");
  lv_obj_set_pos(settings_timeout_dropdown, 140, y - 5);
  lv_obj_set_width(settings_timeout_dropdown, 100);
  // Set current value
  if (deviceTimeoutSeconds == 0) lv_dropdown_set_selected(settings_timeout_dropdown, 0);
  else if (deviceTimeoutSeconds <= 300) lv_dropdown_set_selected(settings_timeout_dropdown, 1);
  else if (deviceTimeoutSeconds <= 1800) lv_dropdown_set_selected(settings_timeout_dropdown, 2);
  else if (deviceTimeoutSeconds <= 3600) lv_dropdown_set_selected(settings_timeout_dropdown, 3);
  else lv_dropdown_set_selected(settings_timeout_dropdown, 4);
  y += line_h + 15;  // Extra spacing to match interval dropdown spacing
  
  // Timezone dropdown (LEFT side)
  lv_obj_t *timezone_label = lv_label_create(settings_screen);
  lv_label_set_text(timezone_label, "Timezone (UTC):");
  lv_obj_set_style_text_font(timezone_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(timezone_label, lv_color_hex(0xCCCCCC), 0);
  lv_obj_set_pos(timezone_label, 20, y);
  
  settings_timezone_dropdown = lv_dropdown_create(settings_screen);
  lv_dropdown_set_options(settings_timezone_dropdown, "-12\n-11\n-10\n-9\n-8\n-7\n-6\n-5\n-4\n-3\n-2\n-1\n0\n+1\n+2\n+3\n+4\n+5\n+6\n+7\n+8\n+9\n+10\n+11\n+12");
  lv_obj_set_pos(settings_timezone_dropdown, 140, y - 5);
  lv_obj_set_width(settings_timezone_dropdown, 100);  // Same width as timeout dropdown
  // Set current value (offset by 12 to get index)
  lv_dropdown_set_selected(settings_timezone_dropdown, timezoneOffsetHours + 12);
  y += line_h + 25;  // Extra spacing before WiFi/Reset buttons
  
  // Change WiFi button (LEFT) and Factory Reset button (RIGHT) on same line
  lv_obj_t *change_wifi_btn = lv_btn_create(settings_screen);
  lv_obj_set_size(change_wifi_btn, 200, 40);
  lv_obj_set_pos(change_wifi_btn, 20, y);
  lv_obj_set_style_bg_color(change_wifi_btn, lv_color_hex(0x4A5568), 0); // Slate gray
  lv_obj_set_style_shadow_width(change_wifi_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(change_wifi_btn, 0, 0);  // No border
  lv_obj_t *change_label = lv_label_create(change_wifi_btn);
  lv_label_set_text(change_label, "Change WiFi Network");
  lv_obj_center(change_label);
  lv_obj_add_event_cb(change_wifi_btn, settings_change_wifi_handler, LV_EVENT_CLICKED, NULL);
  
  // Factory Reset button (RIGHT, 15px from edge, aligned with OUI button)
  lv_obj_t *reset_btn = lv_btn_create(settings_screen);
  lv_obj_set_size(reset_btn, 200, 40);
  lv_obj_align(reset_btn, LV_ALIGN_TOP_RIGHT, -15, y);
  lv_obj_set_style_bg_color(reset_btn, lv_color_hex(0xD97706), 0); // Amber
  lv_obj_set_style_shadow_width(reset_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(reset_btn, 0, 0);  // No border
  lv_obj_t *reset_label = lv_label_create(reset_btn);
  lv_label_set_text(reset_label, LV_SYMBOL_REFRESH " Factory Reset");
  lv_obj_center(reset_label);
  lv_obj_add_event_cb(reset_btn, settings_factory_reset_handler, LV_EVENT_CLICKED, NULL);
  
  y += 50;
  
  // Bottom buttons - Same size as others (200x40)
  lv_obj_t *save_btn = lv_btn_create(settings_screen);
  lv_obj_set_size(save_btn, 200, 40);
  lv_obj_set_pos(save_btn, 20, 420);
  lv_obj_set_style_bg_color(save_btn, lv_color_hex(0x059669), 0); // Muted green
  lv_obj_set_style_shadow_width(save_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(save_btn, 0, 0);  // No border
  lv_obj_t *save_label = lv_label_create(save_btn);
  lv_label_set_text(save_label, "Save & Apply");
  lv_obj_set_style_text_font(save_label, &lv_font_montserrat_14, 0);
  lv_obj_center(save_label);
  lv_obj_add_event_cb(save_btn, settings_save_handler, LV_EVENT_CLICKED, NULL);
  
  lv_obj_t *cancel_btn = lv_btn_create(settings_screen);
  lv_obj_set_size(cancel_btn, 200, 40);
  lv_obj_align(cancel_btn, LV_ALIGN_TOP_RIGHT, -15, 420);
  lv_obj_set_style_bg_color(cancel_btn, lv_color_hex(0xDC2626), 0); // Muted red
  lv_obj_set_style_shadow_width(cancel_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(cancel_btn, 0, 0);  // No border
  lv_obj_t *cancel_label = lv_label_create(cancel_btn);
  lv_label_set_text(cancel_label, "Cancel");
  lv_obj_set_style_text_font(cancel_label, &lv_font_montserrat_14, 0);
  lv_obj_center(cancel_label);
  lv_obj_add_event_cb(cancel_btn, settings_cancel_handler, LV_EVENT_CLICKED, NULL);
  
  xSemaphoreGive(lvgl_mutex);
}

// Update network statistics display
void updateNetworkStats()
{
  if (!main_screen) return;
  
  // --- PART 1: Status Labels (Fast) ---
  // Don't block if LVGL task is busy - skip this update
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
      // WiFi Status
      if (wifiConnected)
      {
        String wifi_text = "WiFi: Connected (" + currentSSID + ")";
        lv_label_set_text(wifi_label, wifi_text.c_str());
        lv_obj_set_style_text_color(wifi_label, lv_color_hex(0x00FF00), 0);
      }
      else
      {
        lv_label_set_text(wifi_label, "WiFi: Disconnected");
        lv_obj_set_style_text_color(wifi_label, lv_color_hex(0xFF0000), 0);
      }
      
      // IP Address
      String ip_text = "IP: " + currentIP;
      lv_label_set_text(ip_label, ip_text.c_str());
      
      // Signal Strength
      if (wifiConnected && WiFi.getMode() == WIFI_STA)
      {
        rssi = WiFi.RSSI();
        String rssi_text = "Signal: " + String(rssi) + " dBm";
        lv_label_set_text(rssi_label, rssi_text.c_str());
        
        // Color code signal strength
        if (rssi > -60)
          lv_obj_set_style_text_color(rssi_label, lv_color_hex(0x00FF00), 0);
        else if (rssi > -75)
          lv_obj_set_style_text_color(rssi_label, lv_color_hex(0xFFFF00), 0);
        else
          lv_obj_set_style_text_color(rssi_label, lv_color_hex(0xFF0000), 0);
      }
      else
      {
        lv_label_set_text(rssi_label, "Signal: --- dBm");
        lv_obj_set_style_text_color(rssi_label, lv_color_hex(0xCCCCCC), 0);
      }
      
      // MAC Address
      String mac = WiFi.macAddress();
      String mac_text = "MAC: " + mac;
      lv_label_set_text(status_label, mac_text.c_str());
      
      // Internet Status
      if (internetConnected)
      {
        lv_label_set_text(internet_label, "Internet: Connected");
        lv_obj_set_style_text_color(internet_label, lv_color_hex(0x00FF00), 0);
      }
      else if (wifiConnected)
      {
        lv_label_set_text(internet_label, "Internet: No connectivity");
        lv_obj_set_style_text_color(internet_label, lv_color_hex(0xFF0000), 0);
      }
      else
      {
        lv_label_set_text(internet_label, "Internet: Unknown");
        lv_obj_set_style_text_color(internet_label, lv_color_hex(0xFFFF00), 0);
      }
      
      // Gateway and DNS info
      if (wifiConnected && WiFi.getMode() == WIFI_STA)
      {
        String gateway_text = "GW: " + WiFi.gatewayIP().toString();
        lv_label_set_text(gateway_label, gateway_text.c_str());
        
        String dns_text = "DNS: " + WiFi.dnsIP(0).toString();
        IPAddress dns2 = WiFi.dnsIP(1);
        if (dns2 != IPAddress(0, 0, 0, 0)) {
          dns_text += ", " + dns2.toString();
        }
        lv_label_set_text(dns_label, dns_text.c_str());
      }
      else
      {
        lv_label_set_text(gateway_label, "GW: ---");
        lv_label_set_text(dns_label, "DNS: ---");
      }
      
      // Public IP
      String public_ip_text = "Public IP: " + publicIP;
      lv_label_set_text(public_ip_label, public_ip_text.c_str());
      
      // Update time display
      if (time_label) {
        struct tm timeinfo;
        if (getLocalTime(&timeinfo)) {
          char timeStr[64];
          strftime(timeStr, sizeof(timeStr), "%H:%M %A %d %b %Y", &timeinfo);
          lv_label_set_text(time_label, timeStr);
        } else {
          lv_label_set_text(time_label, "--:-- --- -- --- ----");
        }
      }
      
      xSemaphoreGive(lvgl_mutex);
  } else {
      return; // Skip if busy
  }
  
  // --- PART 2: Device List (Slow) ---
  // Update device list only if it has changed
  if (deviceListChanged) {
    // Prepare data OUTSIDE of LVGL mutex
    std::vector<String> deviceLines;
    std::vector<uint32_t> deviceColors;
    std::vector<int> deviceIndices;  // Track original device indices
    bool hasDevices = false;
    
    // Protect access to networkDevices vector
    if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
      if (networkDevices.size() > 0) {
        hasDevices = true;
        unsigned long currentTime = millis();
        int displayedCount = 0;
        
        for (size_t i = 0; i < networkDevices.size(); i++) {
          unsigned long ageSeconds = (currentTime - networkDevices[i].lastSeen) / 1000;
          
          // Skip devices that exceeded timeout (if timeout is set)
          if (deviceTimeoutSeconds > 0 && ageSeconds > deviceTimeoutSeconds) {
            continue;  // Don't display this device
          }
          
          displayedCount++;
          
          String deviceText = "";
          uint32_t color = 0x00FF00; // Green default
          
          // ===== 3-TIER DEVICE IDENTIFICATION SYSTEM =====
          // Each device gets a label with a color indicating the source of information:
          //
          // PRIORITY 1 - YELLOW (0xFFFF00): Hostname from network queries
          //   - Most specific identification (e.g., "iPhone", "LGwebOSTV")
          //   - Obtained via ReverseDNS or UPnP queries
          //   - Displayed as: *hostname* (IP) - MAC
          //
          // PRIORITY 2 - ORANGE (0xFFA500): Vendor from IEEE OUI Database (38,439 vendors)
          //   - Manufacturer identified via binary search in sorted index
          //   - Uses 6MB IEEE database on SD card
          //   - Displayed as: [Vendor] IP - MAC
          //
          // PRIORITY 3 - GREEN (0x00FF00): Vendor from hardcoded common vendors
          //   - Fast fallback for ~200 common manufacturers
          //   - No SD card required
          //   - Displayed as: [Vendor] IP - MAC
          //
          // Note: Yellow always wins - if we get a hostname, we show that instead of vendor
          
          if (networkDevices[i].name.length() > 0) {
            // Actual hostname - show in YELLOW with asterisks
            deviceText = String(displayedCount) + ": *" + networkDevices[i].name + "*";
            deviceText += " (" + networkDevices[i].ip + ")";
            deviceText += " - " + networkDevices[i].mac;
            color = 0xFFFF00; // Yellow
          } else {
            // No hostname - use cached vendor name from device struct
            if (networkDevices[i].vendor.length() > 0) {
              // Vendor found - show in brackets (truncate for list display)
              // Orange if from SD database, Green if from hardcoded
              String vendorDisplay = networkDevices[i].vendor;
              if (vendorDisplay.length() > 20) {
                vendorDisplay = vendorDisplay.substring(0, 17) + "...";
              }
              deviceText = String(displayedCount) + ": [" + vendorDisplay + "] " + networkDevices[i].ip;
              color = networkDevices[i].vendorFromSD ? 0xFFA500 : 0x00FF00; // Orange or Green
            } else {
              deviceText = String(displayedCount) + ": " + networkDevices[i].ip;
              color = 0x00FF00; // Green
            }
            deviceText += " - " + networkDevices[i].mac;
          }
          
          // Show how long ago device was seen
          if (ageSeconds < 60) {
            deviceText += " (" + String(ageSeconds) + "s)";
          } else {
            deviceText += " (" + String(ageSeconds / 60) + "m)";
          }
          
          deviceLines.push_back(deviceText);
          deviceColors.push_back(color);
          deviceIndices.push_back(i);  // Store original device index
        }
      }
      xSemaphoreGive(devices_mutex);
    }
    
    // Now update UI with prepared data
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        lv_obj_clean(device_list);
        
        // Add this device first - single line
        lv_obj_t *me_label = lv_label_create(device_list);
        String meText = "[ME] MAC: " + WiFi.macAddress() + " IP: " + currentIP;
        if (WiFi.getMode() == WIFI_STA && rssi != 0) {
          meText += " RSSI: " + String(rssi) + "dBm";
        }
        lv_label_set_text(me_label, meText.c_str());
        lv_obj_set_style_text_font(me_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(me_label, lv_color_hex(0x00FF00), 0);
        lv_obj_set_width(me_label, lv_pct(100));
        
        // Spacing label
        lv_obj_t *spacer = lv_label_create(device_list);
        lv_label_set_text(spacer, "");
        
        if (hasDevices) {
            for (size_t i = 0; i < deviceLines.size(); i++) {
                // Create a container for the device item (makes it easier to click)
                lv_obj_t *dev_container = lv_obj_create(device_list);
                lv_obj_set_width(dev_container, lv_pct(100));
                lv_obj_set_height(dev_container, LV_SIZE_CONTENT);
                lv_obj_set_style_bg_color(dev_container, COLOR_BUTTON, 0);  // Button-like background
                lv_obj_set_style_bg_opa(dev_container, LV_OPA_COVER, 0);  // Solid background
                lv_obj_set_style_border_width(dev_container, 0, 0);   // No border
                lv_obj_set_style_shadow_width(dev_container, 0, 0);   // No shadow
                lv_obj_set_style_radius(dev_container, 3, 0);         // Slight rounding
                lv_obj_set_style_pad_all(dev_container, 5, 0);        // Padding for button feel
                
                // Create label inside container
                lv_obj_t *dev_label = lv_label_create(dev_container);
                lv_obj_set_style_text_font(dev_label, &lv_font_montserrat_14, 0);
                lv_obj_set_width(dev_label, lv_pct(100));
                lv_label_set_text(dev_label, deviceLines[i].c_str());
                lv_obj_set_style_text_color(dev_label, lv_color_hex(deviceColors[i]), 0);
                
                // Allocate memory for device index (will be freed when object is deleted)
                int *dev_idx = (int*)malloc(sizeof(int));
                *dev_idx = deviceIndices[i];
                
                // Make container clickable and attach device index
                lv_obj_add_flag(dev_container, LV_OBJ_FLAG_CLICKABLE);
                lv_obj_add_event_cb(dev_container, device_label_click_handler, LV_EVENT_CLICKED, dev_idx);
                
                // Add visual feedback on press - slightly darker
                lv_obj_set_style_bg_opa(dev_container, LV_OPA_COVER, LV_STATE_PRESSED);
                lv_obj_set_style_bg_color(dev_container, lv_color_hex(0x1a1a1a), LV_STATE_PRESSED);
            }
        } else if (initialScanDone) {
            lv_obj_t *msg_label = lv_label_create(device_list);
            lv_label_set_text(msg_label, "No devices found in ARP table.\nDevices appear when they\ncommunicate on the network.\nScanning automatically every 5s...");
            lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_14, 0);
            lv_obj_set_style_text_color(msg_label, lv_color_hex(0x00FF00), 0);
            lv_obj_set_width(msg_label, lv_pct(100));
        } else {
            lv_obj_t *scan_label = lv_label_create(device_list);
            lv_label_set_text(scan_label, "Scanning network...");
            lv_obj_set_style_text_font(scan_label, &lv_font_montserrat_14, 0);
            lv_obj_set_style_text_color(scan_label, lv_color_hex(0x00FF00), 0);
            lv_obj_set_width(scan_label, lv_pct(100));
        }
        
        xSemaphoreGive(lvgl_mutex);
        deviceListChanged = false;
    }
  }
}

// WiFi event handler
void WiFiEvent(WiFiEvent_t event)
{
  switch (event)
  {
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      wifiConnected = true;
      currentSSID = WiFi.SSID();
      currentIP = WiFi.localIP().toString();
      internetConnected = (WiFi.status() == WL_CONNECTED);
      Serial.println("[WiFi] Connected to " + currentSSID);
      Serial.println("[WiFi] IP: " + currentIP);
      Serial.printf("[WiFi] Internet: %s\n", internetConnected ? "Connected" : "No connectivity");
      break;
      
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      wifiConnected = false;
      internetConnected = false;
      currentIP = "";
      Serial.println("[WiFi] Disconnected");
      break;
      
    case ARDUINO_EVENT_WIFI_AP_START:
      currentSSID = WiFi.softAPSSID();
      currentIP = WiFi.softAPIP().toString();
      wifiConnected = true;
      Serial.println("[WiFi] AP Started: " + currentSSID);
      Serial.println("[WiFi] AP IP: " + currentIP);
      break;
      
    default:
      break;
  }
}

// Initialize WiFi
void initWiFi()
{
  WiFi.onEvent(WiFiEvent);
  
  String ssid = getConfigValue(0);  // WiFi SSID
  String password = getConfigValue(1);  // WiFi Password
  
  // Load network scanner settings from config
  activeProbeEnabled = (getConfigValue(4) == "1");
  probeIntervalSeconds = getConfigValue(5).toInt();
  deviceTimeoutSeconds = getConfigValue(6).toInt();
  timezoneOffsetHours = getConfigValue(7).toInt();
  if (probeIntervalSeconds < 5) probeIntervalSeconds = 30;  // Minimum 5 seconds
  Serial.printf("[Config] Active Probe: %s, Interval: %ds, Timeout: %ds, Timezone: UTC%+d\n", 
                activeProbeEnabled ? "ON" : "OFF", probeIntervalSeconds, deviceTimeoutSeconds, timezoneOffsetHours);
  
  if (ssid.length() > 0)
  {
    // Show splash screen with connection status
    String connect_msg = "Connecting to " + ssid + "...";
    createSplashScreen(connect_msg.c_str());
    
    // Brief delay to allow WiFi hardware to stabilize
    delay(1500);
    
    // Try to connect to the specified network in Station mode
    Serial.println("[WiFi] Attempting to connect to " + ssid);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid.c_str(), password.c_str());
    
    // Wait for connection (timeout 10 seconds)
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20)
    {
      vTaskDelay(pdMS_TO_TICKS(500));
      Serial.print(".");
      attempts++;
      
      // Let LVGL task handle updates - no manual updates to prevent flickering
    }
    
    if (WiFi.status() == WL_CONNECTED)
    {
      Serial.println("\n[WiFi] Connected in STA mode!");
      
      // Configure NTP time sync now that we have WiFi
      configTime(timezoneOffsetHours * 3600, 0, "pool.ntp.org", "time.nist.gov");
      Serial.println("[NTP] Time sync configured");
      
      // Wait for NTP sync (up to 10 seconds)
      Serial.print("[NTP] Waiting for time sync...");
      struct tm timeinfo;
      int ntp_retry = 0;
      while (!getLocalTime(&timeinfo) && ntp_retry < 20) {
        Serial.print(".");
        vTaskDelay(pdMS_TO_TICKS(500));
        ntp_retry++;
      }
      if (getLocalTime(&timeinfo)) {
        Serial.println(" SUCCESS!");
        char timeStr[64];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
        Serial.printf("[NTP] Current time: %s\n", timeStr);
      } else {
        Serial.println(" TIMEOUT (will retry in background)");
      }
      
      // Setup mDNS
      if (MDNS.begin("network-analyzer")) {
        Serial.println("[mDNS] Responder started");
      }
      
      // Setup OTA
      ArduinoOTA.setHostname("network-analyzer");
      ArduinoOTA.begin();
      
      // Check for manual OUI update request (from settings panel)
      if (sdCardReady && sdFileMutex && SD.exists(OUI_PENDING_FILE)) {
        Serial.println("[INIT] Manual OUI update requested - downloading now...");
        
        // Remove the pending flag
        if (xSemaphoreTake(sdFileMutex, pdMS_TO_TICKS(2000)) == pdTRUE) {
          SD.remove(OUI_PENDING_FILE);
          xSemaphoreGive(sdFileMutex);
        }
        
        // Create progress screen for download
        createOUIProgressScreen("Downloading Database");
        vTaskDelay(pdMS_TO_TICKS(200)); // Let screen render
        
        // Download the database (checks SD card internally)
        downloadOUIDatabase();
        
        // Build the index only if database exists
        if (sdCardReady && sdFileMutex && SD.exists(OUI_DATABASE_FILE)) {
          Serial.println("[INIT] Building OUI index...");
          buildOUIIndex();
        } else {
          Serial.println("[INIT] Database not found after download - skipping index build");
        }
        
        Serial.println("[INIT] OUI update complete - rebooting...");
        ESP.restart();
      }
      
      // ===== OUI DATABASE DOWNLOAD CHECK =====
      // Check if the IEEE OUI database needs updating - prompt user BEFORE starting all tasks
      // 
      // WHEN DOWNLOAD HAPPENS:
      // 1. Database file missing (first boot)
      // 2. Database file too small (<1MB = corrupted)
      // 3. Database older than 30 days (stale vendor data)
      // 
      // WHY BEFORE TASKS:
      // - Ensures memory is available (download uses ~4KB buffer)
      // - SD card is stable (no concurrent access)
      // - Device reboots after download for clean state
      // 
      // USER CHOICE:
      // - "Update & Reboot": Downloads 6MB IEEE database (~60 seconds), then reboots
      // - "Skip": Continues with existing database (or hardcoded vendors if none)
      if (sdCardReady && sdFileMutex && needsOUIUpdate()) {
        Serial.println("[INIT] OUI database update required - prompting user");
        handleOUIUpdateFlow();
        // If we get here, user chose to skip - continue normally
        Serial.println("[INIT] User skipped OUI update - continuing with existing database");
      }
      
      // ===== OUI INDEX BUILDING CHECK =====
      // The sorted index enables binary search for instant vendor lookups
      // Without it, we'd need to scan all 38,439 lines (20-30 seconds per lookup!)
      // 
      // INDEX BUILDING TRIGGERS (automatic, no user prompt):
      // 1. Index file missing (/oui.idx doesn't exist)
      // 2. Index file corrupted (size < 100KB, should be ~600KB)
      // 
      // BUILD PROCESS:
      // - Takes ~60-90 seconds on first boot
      // - Creates sorted index with 38,439 entries
      // - Uses memory-efficient chunked merge sort (only 20KB RAM at a time)
      // - Shows progress screen during build
      // 
      // RESULT:
      // - Binary search can find any vendor in ~15 comparisons (0.1 seconds)
      // - Index persists on SD card - only builds once unless corrupted
      if (sdCardReady && sdFileMutex && SD.exists(OUI_DATABASE_FILE)) {
        bool needsIndexRebuild = false;
        
        if (!SD.exists(OUI_INDEX_FILE)) {
          Serial.println("[INIT] OUI index missing - will build automatically");
          needsIndexRebuild = true;
        } else {
          // Check if index is valid (should be ~500-800KB for 38K+ entries)
          File idxCheck = SD.open(OUI_INDEX_FILE, FILE_READ);
          if (idxCheck) {
            size_t idxSize = idxCheck.size();
            idxCheck.close();
            if (idxSize < 100000) {  // Less than 100KB = corrupted/incomplete
              Serial.printf("[INIT] OUI index too small (%d bytes) - will rebuild\n", idxSize);
              needsIndexRebuild = true;
            }
          }
        }
        
        if (needsIndexRebuild) {
          Serial.println("[INIT] Building sorted OUI index automatically...");
          createOUIProgressScreen("Building Sorted Index");
          vTaskDelay(pdMS_TO_TICKS(200));
          buildOUIIndex();
          destroyOUIProgressScreen();
          Serial.println("[INIT] OUI index build complete");
        }
      }
    }
    else
    {
      Serial.println("\n[WiFi] Failed to connect, falling back to AP mode");
      
      // Update splash screen
      createSplashScreen("Connection failed\nStarting AP mode...");
      delay(1500);
      
      WiFi.mode(WIFI_AP);
      String apSSID = getConfigValue(2);  // AP SSID
      String apPassword = getConfigValue(3);  // AP Password
      if (apSSID == "" || apPassword == "") {
        apSSID = "Network Analyser";
        apPassword = "Epoxy123";
      }
      WiFi.softAP(apSSID.c_str(), apPassword.c_str());
    }
  }
  else
  {
    // No SSID configured - start in AP mode
    Serial.println("[WiFi] No SSID configured. Starting AP mode...");
    createSplashScreen("No WiFi configured\nStarting AP mode...");
    delay(1500);
    
    WiFi.mode(WIFI_AP);
    String apSSID = getConfigValue(2);  // AP SSID
    String apPassword = getConfigValue(3);  // AP Password
    if (apSSID == "" || apPassword == "") {
      apSSID = "Network Analyser";
      apPassword = "Epoxy123";
    }
    WiFi.softAP(apSSID.c_str(), apPassword.c_str());
  }
}

// Download IEEE OUI database to SD card
// Check if OUI database needs updating (returns true if download needed)
bool needsOUIUpdate() {
  // Match NMEATouch20 pattern: check both flag and mutex existence
  if (!(sdCardReady && sdFileMutex)) {
    return false;  // Silent return - SD not ready, no update possible
  }
  
  // Acquire SD mutex for thread-safe access
  if (xSemaphoreTake(sdFileMutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
    Serial.println("[OUI DB] Failed to acquire SD mutex");
    return false;
  }
  
  Serial.println("[OUI DB] Checking if database needs update...");
  
  // Check if database file exists and has valid size
  if (!SD.exists(OUI_DATABASE_FILE)) {
    Serial.println("[OUI DB] Database not found - needs download");
    xSemaphoreGive(sdFileMutex);
    return true;
  }
  
  // Log database file size and validate
  File dbFile = SD.open(OUI_DATABASE_FILE, FILE_READ);
  if (dbFile) {
    size_t fileSize = dbFile.size();
    Serial.printf("[OUI DB] Current database size: %d bytes\n", fileSize);
    dbFile.close();
    
    // File must be > 1MB to be considered valid
    if (fileSize < 1000000) {
      Serial.printf("[OUI DB] Database file too small (%d bytes) - needs download\n", fileSize);
      xSemaphoreGive(sdFileMutex);
      return true;
    }
  } else {
    Serial.println("[OUI DB] Cannot open database file - needs download");
    xSemaphoreGive(sdFileMutex);
    return true;
  }
  
  // Check timestamp file
  if (!SD.exists(OUI_TIMESTAMP_FILE)) {
    Serial.println("[OUI DB] No timestamp found - needs update");
    xSemaphoreGive(sdFileMutex);
    return true;
  }
  
  // Read last update time
  File tsFile = SD.open(OUI_TIMESTAMP_FILE, FILE_READ);
  if (!tsFile) {
    Serial.println("[OUI DB] Cannot read timestamp - needs update");
    xSemaphoreGive(sdFileMutex);
    return true;
  }
  
  String timestampStr = tsFile.readStringUntil('\n');
  tsFile.close();
  
  unsigned long lastUpdate = timestampStr.toInt();
  unsigned long currentTime = time(nullptr);
  
  // Check if current time is valid (NTP synced)
  if (currentTime < 1000000000) {
    Serial.println("[OUI DB] Time not synced yet - skipping update check");
    xSemaphoreGive(sdFileMutex);
    return false;
  }
  
  unsigned long age = currentTime - lastUpdate;
  Serial.printf("[OUI DB] Database age: %lu days\n", age / (24 * 60 * 60));
  
  bool needsUpdate = (age > OUI_UPDATE_INTERVAL);
  if (needsUpdate) {
    Serial.println("[OUI DB] Database outdated - needs update");
  } else {
    Serial.println("[OUI DB] Database is current");
  }
  
  xSemaphoreGive(sdFileMutex);
  return needsUpdate;
}

void createOUIProgressScreen(const char* title_text) {
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
    return;
  }
  
  // Create a new full-screen as the main screen
  ouiProgressScreen = lv_obj_create(NULL);
  lv_obj_set_style_bg_color(ouiProgressScreen, lv_color_hex(0x000000), 0);
  
  // Title
  lv_obj_t* title = lv_label_create(ouiProgressScreen);
  lv_label_set_text(title, title_text);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_color(title, lv_color_hex(0xFFFFFF), 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 60);
  
  // Progress bar
  ouiProgressBar = lv_bar_create(ouiProgressScreen);
  lv_obj_set_size(ouiProgressBar, TFT_WIDTH - 100, 30);
  lv_obj_align(ouiProgressBar, LV_ALIGN_CENTER, 0, 0);
  lv_bar_set_range(ouiProgressBar, 0, 6000); // 6000 KB = ~6 MB
  lv_bar_set_value(ouiProgressBar, 0, LV_ANIM_OFF);
  lv_obj_set_style_bg_color(ouiProgressBar, lv_color_hex(0x404040), LV_PART_MAIN);
  lv_obj_set_style_bg_color(ouiProgressBar, lv_color_hex(0x00AA00), LV_PART_INDICATOR);
  
  // Progress label
  ouiProgressLabel = lv_label_create(ouiProgressScreen);
  lv_label_set_text(ouiProgressLabel, "0.0 MB / 6.0 MB");
  lv_obj_set_style_text_font(ouiProgressLabel, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(ouiProgressLabel, lv_color_hex(0xFFFFFF), 0);
  lv_obj_align(ouiProgressLabel, LV_ALIGN_CENTER, 0, 50);
  
  // Load this screen as the active screen
  lv_scr_load(ouiProgressScreen);
  
  xSemaphoreGive(lvgl_mutex);
}

void destroyOUIProgressScreen() {
  if (!ouiProgressScreen) return;
  
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
    return;
  }
  
  // Switch back to main screen before deleting
  if (main_screen) {
    lv_scr_load(main_screen);
  }
  
  // Delete the progress screen
  lv_obj_del(ouiProgressScreen);
  ouiProgressScreen = nullptr;
  ouiProgressBar = nullptr;
  ouiProgressLabel = nullptr;
  
  xSemaphoreGive(lvgl_mutex);
}

// Get common service name for a port
String getServiceName(uint16_t port) {
  switch(port) {
    case 21: return "FTP";
    case 22: return "SSH";
    case 23: return "Telnet";
    case 25: return "SMTP";
    case 53: return "DNS";
    case 80: return "HTTP";
    case 110: return "POP3";
    case 143: return "IMAP";
    case 443: return "HTTPS";
    case 445: return "SMB";
    case 3306: return "MySQL";
    case 3389: return "RDP";
    case 5432: return "PostgreSQL";
    case 5900: return "VNC";
    case 8080: return "HTTP-Alt";
    case 8443: return "HTTPS-Alt";
    case 9000: return "SonarQube";
    default: return "Unknown";
  }
}

// Port scan task function
void PortScanTask(void *parameter) {
  String ip = *((String*)parameter);
  delete (String*)parameter;  // Free the allocated string
  
  current_port_scan.clear();
  port_scan_in_progress = true;
  
  // Common ports to scan
  uint16_t ports[] = {21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443, 9000};
  int num_ports = sizeof(ports) / sizeof(ports[0]);
  
  Serial.printf("[Port Scan] Scanning %s for open ports...\n", ip.c_str());
  
  for (int i = 0; i < num_ports; i++) {
    WiFiClient client;
    bool is_open = false;
    
    // Try to connect with 500ms timeout
    client.setTimeout(500);
    if (client.connect(ip.c_str(), ports[i], 500)) {
      is_open = true;
      client.stop();
      Serial.printf("[Port Scan] Port %d (%s) is OPEN\n", ports[i], getServiceName(ports[i]).c_str());
    }
    
    PortScanResult result;
    result.port = ports[i];
    result.is_open = is_open;
    result.service_name = getServiceName(ports[i]);
    current_port_scan.push_back(result);
    
    vTaskDelay(pdMS_TO_TICKS(10)); // Small delay to allow UI updates
  }
  
  port_scan_in_progress = false;
  Serial.printf("[Port Scan] Scan complete - found %d open ports\n", 
                std::count_if(current_port_scan.begin(), current_port_scan.end(), 
                             [](const PortScanResult& r) { return r.is_open; }));
  
  need_details_refresh = true;  // Signal UI to refresh
  port_scan_task_handle = NULL;
  vTaskDelete(NULL);  // Delete this task
}

// Ping task function
void PingTask(void *parameter) {
  String ip = *((String*)parameter);
  delete (String*)parameter;  // Free the allocated string
  
  ping_in_progress = true;
  current_ping_stats = PingStats(); // Reset stats
  
  Serial.printf("[Ping] Pinging %s...\n", ip.c_str());
  
  IPAddress target;
  if (!target.fromString(ip)) {
    Serial.println("[Ping] Invalid IP address");
    ping_in_progress = false;
    return;
  }
  
  const int num_pings = 5;
  float times[num_pings];
  int successful = 0;
  
  for (int i = 0; i < num_pings; i++) {
    current_ping_stats.packets_sent++;
    
    // Use ICMP ping
    if (Ping.ping(target, 1)) {
      float time_ms = Ping.averageTime();
      times[successful] = time_ms;
      successful++;
      current_ping_stats.packets_received++;
      
      Serial.printf("[Ping] Reply from %s: time=%.2fms\n", ip.c_str(), time_ms);
    } else {
      Serial.printf("[Ping] Request timed out\n");
    }
    
    vTaskDelay(pdMS_TO_TICKS(1000)); // Wait 1 second between pings
  }
  
  // Calculate statistics
  if (successful > 0) {
    current_ping_stats.min_ms = times[0];
    current_ping_stats.max_ms = times[0];
    float sum = 0;
    
    for (int i = 0; i < successful; i++) {
      if (times[i] < current_ping_stats.min_ms) current_ping_stats.min_ms = times[i];
      if (times[i] > current_ping_stats.max_ms) current_ping_stats.max_ms = times[i];
      sum += times[i];
    }
    
    current_ping_stats.avg_ms = sum / successful;
  }
  
  Serial.printf("[Ping] Statistics: %d/%d packets received (%.0f%% loss)\n",
                current_ping_stats.packets_received, current_ping_stats.packets_sent,
                100.0 * (1.0 - (float)current_ping_stats.packets_received / current_ping_stats.packets_sent));
  
  need_details_refresh = true;  // Signal UI to refresh
  ping_in_progress = false;
  ping_task_handle = NULL;
  vTaskDelete(NULL);  // Delete this task
}

// Back button handler for device details screen
static void details_back_btn_handler(lv_event_t *e) {
  destroyDeviceDetailsScreen();
}

// Device label click handler
static void device_label_click_handler(lv_event_t *e) {
  // Get the device index from user data
  int *device_idx_ptr = (int*)lv_event_get_user_data(e);
  if (device_idx_ptr) {
    int device_idx = *device_idx_ptr;
    Serial.printf("[UI] Device %d clicked - opening details\n", device_idx);
    createDeviceDetailsScreen(device_idx);
  }
}

// Port scan button handler
static void port_scan_btn_handler(lv_event_t *e) {
  if (selected_device_index < 0) return;
  
  // Safety check: if flag is stuck but task is gone, reset it
  if (port_scan_in_progress && port_scan_task_handle == NULL) {
    Serial.println("[Port Scan] Resetting stuck port scan flag");
    port_scan_in_progress = false;
  }
  
  if (port_scan_in_progress) return;
  
  if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    if (selected_device_index < networkDevices.size()) {
      String ip = networkDevices[selected_device_index].ip;
      xSemaphoreGive(devices_mutex);
      
      // Create task for port scanning
      String* ip_ptr = new String(ip);
      xTaskCreatePinnedToCore(PortScanTask, "PortScan", 4096, (void*)ip_ptr, 1, &port_scan_task_handle, 0);
      
      Serial.printf("[Port Scan] Task created for %s\n", ip.c_str());
    } else {
      xSemaphoreGive(devices_mutex);
    }
  }
}

// Ping button handler
static void ping_btn_handler(lv_event_t *e) {
  if (selected_device_index < 0) return;
  
  // Safety check: if flag is stuck but task is gone, reset it
  if (ping_in_progress && ping_task_handle == NULL) {
    Serial.println("[Ping] Resetting stuck ping flag");
    ping_in_progress = false;
  }
  
  if (ping_in_progress) return;
  
  if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    if (selected_device_index < networkDevices.size()) {
      String ip = networkDevices[selected_device_index].ip;
      xSemaphoreGive(devices_mutex);
      
      // Create task for pinging
      String* ip_ptr = new String(ip);
      xTaskCreatePinnedToCore(PingTask, "Ping", 4096, (void*)ip_ptr, 1, &ping_task_handle, 0);
      
      Serial.printf("[Ping] Task created for %s\n", ip.c_str());
    } else {
      xSemaphoreGive(devices_mutex);
    }
  }
}

// Create device details screen
void createDeviceDetailsScreen(int device_index) {
  Serial.printf("[Details] createDeviceDetailsScreen called for device %d\n", device_index);
  
  // NOTE: No mutex needed here - this is called from LVGL event handler which already has the mutex
  
  // Clear previous scan results ONLY if switching to a different device
  if (scan_results_for_device != device_index) {
    Serial.printf("[Details] Different device (was %d, now %d) - clearing previous results\n", scan_results_for_device, device_index);
    current_port_scan.clear();
    current_ping_stats = PingStats();  // Reset to default values
    port_scan_in_progress = false;
    ping_in_progress = false;
    scan_results_for_device = device_index;
  }
  
  Serial.println("[Details] Creating screen");
  selected_device_index = device_index;
  
  // Create screen
  details_screen = lv_obj_create(NULL);
  lv_obj_set_style_bg_color(details_screen, lv_color_hex(0x000000), 0);
  Serial.println("[Details] Screen created");
  
  // Get device info
  String device_name = "";
  String device_ip = "";
  String device_mac = "";
  String device_vendor = "";
  bool vendor_from_sd = false;
  
  if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    if (device_index < networkDevices.size()) {
      device_name = networkDevices[device_index].name;
      device_ip = networkDevices[device_index].ip;
      device_mac = networkDevices[device_index].mac;
      device_vendor = networkDevices[device_index].vendor;
      vendor_from_sd = networkDevices[device_index].vendorFromSD;
      Serial.printf("[Details] Got device info: %s / %s\n", device_ip.c_str(), device_mac.c_str());
    } else {
      Serial.printf("[Details] ERROR: device_index %d >= size %d\n", device_index, networkDevices.size());
    }
    xSemaphoreGive(devices_mutex);
  } else {
    Serial.println("[Details] Failed to take devices mutex!");
  }
  
  // Back button - align with settings button height
  lv_obj_t *back_btn = lv_btn_create(details_screen);
  lv_obj_set_size(back_btn, 80, 40);
  lv_obj_align(back_btn, LV_ALIGN_TOP_LEFT, 10, 2);
  lv_obj_add_event_cb(back_btn, details_back_btn_handler, LV_EVENT_CLICKED, NULL);
  lv_obj_set_style_bg_color(back_btn, COLOR_BUTTON, 0);
  lv_obj_set_style_shadow_width(back_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(back_btn, 0, 0);  // No border
  lv_obj_t *back_label = lv_label_create(back_btn);
  lv_label_set_text(back_label, "Back");
  lv_obj_center(back_label);
  
  // IP address in header (just IP, no vendor)
  lv_obj_t *header_label = lv_label_create(details_screen);
  lv_label_set_text(header_label, device_ip.c_str());
  lv_obj_set_style_text_font(header_label, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_color(header_label, lv_color_hex(0xFFFFFF), 0);
  lv_obj_align(header_label, LV_ALIGN_TOP_MID, 0, 15);
  
  // Content area (scrollable) - moved up for better layout
  details_content = lv_obj_create(details_screen);
  lv_obj_set_size(details_content, 460, 420);
  lv_obj_set_pos(details_content, 10, 50);
  lv_obj_set_style_bg_opa(details_content, LV_OPA_TRANSP, 0);  // Transparent
  lv_obj_set_style_border_width(details_content, 0, 0);  // Remove border
  lv_obj_set_style_radius(details_content, 0, 0);  // Remove rounded corners
  lv_obj_set_flex_flow(details_content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(details_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
  lv_obj_set_scrollbar_mode(details_content, LV_SCROLLBAR_MODE_AUTO);
  
  // Hostname/Name (if available)
  if (device_name.length() > 0) {
    lv_obj_t *name_label = lv_label_create(details_content);
    String name_text = "Hostname: " + device_name;
    lv_label_set_text(name_label, name_text.c_str());
    lv_obj_set_style_text_font(name_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(name_label, COLOR_WARNING, 0);
    lv_obj_set_width(name_label, lv_pct(100));
  }
  
  // Vendor/OUI - full width field with long text support
  if (device_vendor.length() > 0) {
    lv_obj_t *vendor_label = lv_label_create(details_content);
    lv_label_set_text(vendor_label, device_vendor.c_str());
    lv_obj_set_style_text_font(vendor_label, &lv_font_montserrat_18, 0);
    uint32_t vendor_color = vendor_from_sd ? 0xFFA500 : 0x00FF00;  // Orange for SD, Green for hardcoded
    lv_obj_set_style_text_color(vendor_label, lv_color_hex(vendor_color), 0);
    lv_obj_set_width(vendor_label, lv_pct(100));
    lv_label_set_long_mode(vendor_label, LV_LABEL_LONG_WRAP);  // Allow wrapping for long vendor names
  }
  
  // MAC Address
  lv_obj_t *mac_label = lv_label_create(details_content);
  String mac_text = "MAC: " + device_mac;
  lv_label_set_text(mac_label, mac_text.c_str());
  lv_obj_set_style_text_font(mac_label, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(mac_label, COLOR_TEXT, 0);
  lv_obj_set_width(mac_label, lv_pct(100));
  
  // Spacer (smaller since buttons moved up)
  lv_obj_t *spacer1 = lv_label_create(details_content);
  lv_label_set_text(spacer1, "");
  
  // Extra spacer to push buttons down 20px
  lv_obj_t *spacer2 = lv_label_create(details_content);
  lv_label_set_text(spacer2, "");
  
  // Main container for both button rows
  lv_obj_t *button_container = lv_obj_create(details_content);
  lv_obj_set_width(button_container, lv_pct(100));
  lv_obj_set_height(button_container, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(button_container, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(button_container, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_bg_opa(button_container, LV_OPA_0, 0);
  lv_obj_set_style_border_width(button_container, 0, 0);
  lv_obj_set_style_pad_all(button_container, 0, 0);
  
  // Port scan button container (LED + button)
  lv_obj_t *scan_container = lv_obj_create(button_container);
  lv_obj_set_width(scan_container, lv_pct(48));
  lv_obj_set_height(scan_container, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(scan_container, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(scan_container, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_bg_opa(scan_container, LV_OPA_0, 0);
  lv_obj_set_style_border_width(scan_container, 0, 0);
  lv_obj_set_style_pad_all(scan_container, 0, 0);
  
  // Port scan LED
  details_port_scan_led = lv_obj_create(scan_container);
  lv_obj_set_size(details_port_scan_led, 12, 12);
  lv_obj_set_style_radius(details_port_scan_led, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(details_port_scan_led, COLOR_INDICATOR_OFF, 0);
  lv_obj_set_style_border_width(details_port_scan_led, 0, 0);
  lv_obj_clear_flag(details_port_scan_led, LV_OBJ_FLAG_SCROLLABLE);
  
  // Port scan button
  lv_obj_t *scan_btn = lv_btn_create(scan_container);
  lv_obj_set_flex_grow(scan_btn, 1);
  if (port_scan_in_progress || ping_in_progress) {
    lv_obj_set_style_bg_color(scan_btn, lv_color_hex(0x202020), 0);  // Darker gray when disabled
    lv_obj_add_state(scan_btn, LV_STATE_DISABLED);
  } else {
    lv_obj_set_style_bg_color(scan_btn, COLOR_BUTTON, 0);
  }
  lv_obj_set_style_shadow_width(scan_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(scan_btn, 0, 0);  // No border
  lv_obj_add_event_cb(scan_btn, port_scan_btn_handler, LV_EVENT_CLICKED, NULL);
  lv_obj_t *scan_btn_label = lv_label_create(scan_btn);
  lv_label_set_text(scan_btn_label, port_scan_in_progress ? "Scanning..." : "Scan Ports");
  lv_obj_center(scan_btn_label);
  
  // Ping button container (LED + button)
  lv_obj_t *ping_container = lv_obj_create(button_container);
  lv_obj_set_width(ping_container, lv_pct(48));
  lv_obj_set_height(ping_container, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(ping_container, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(ping_container, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_bg_opa(ping_container, LV_OPA_0, 0);
  lv_obj_set_style_border_width(ping_container, 0, 0);
  lv_obj_set_style_pad_all(ping_container, 0, 0);
  
  // Ping LED
  details_ping_led = lv_obj_create(ping_container);
  lv_obj_set_size(details_ping_led, 12, 12);
  lv_obj_set_style_radius(details_ping_led, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(details_ping_led, COLOR_INDICATOR_OFF, 0);
  lv_obj_set_style_border_width(details_ping_led, 0, 0);
  lv_obj_clear_flag(details_ping_led, LV_OBJ_FLAG_SCROLLABLE);
  
  // Ping button
  lv_obj_t *ping_btn = lv_btn_create(ping_container);
  lv_obj_set_flex_grow(ping_btn, 1);
  if (port_scan_in_progress || ping_in_progress) {
    lv_obj_set_style_bg_color(ping_btn, lv_color_hex(0x202020), 0);  // Darker gray when disabled
    lv_obj_add_state(ping_btn, LV_STATE_DISABLED);
  } else {
    lv_obj_set_style_bg_color(ping_btn, COLOR_BUTTON, 0);
  }
  lv_obj_set_style_shadow_width(ping_btn, 0, 0);  // No shadow
  lv_obj_set_style_border_width(ping_btn, 0, 0);  // No border
  lv_obj_add_event_cb(ping_btn, ping_btn_handler, LV_EVENT_CLICKED, NULL);
  lv_obj_t *ping_btn_label = lv_label_create(ping_btn);
  lv_label_set_text(ping_btn_label, ping_in_progress ? "Pinging..." : "Ping (5x)");
  lv_obj_center(ping_btn_label);
  
  // Container for results (two columns)
  lv_obj_t *results_container = lv_obj_create(details_content);
  lv_obj_set_width(results_container, lv_pct(100));
  lv_obj_set_height(results_container, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(results_container, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(results_container, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
  lv_obj_set_style_bg_opa(results_container, LV_OPA_0, 0);
  lv_obj_set_style_border_width(results_container, 0, 0);
  lv_obj_set_style_pad_all(results_container, 5, 0);
  
  // Left column - Port scan results
  lv_obj_t *port_column = lv_obj_create(results_container);
  lv_obj_set_width(port_column, lv_pct(48));
  lv_obj_set_height(port_column, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(port_column, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_bg_opa(port_column, LV_OPA_0, 0);
  lv_obj_set_style_border_width(port_column, 0, 0);
  lv_obj_set_style_pad_all(port_column, 2, 0);
  
  // Show port scan results if available
  if (current_port_scan.size() > 0) {
    int open_count = 0;
    for (const auto& result : current_port_scan) {
      if (result.is_open) {
        lv_obj_t *port_label = lv_label_create(port_column);
        String port_text = String(result.port) + " " + result.service_name;
        lv_label_set_text(port_label, port_text.c_str());
        lv_obj_set_style_text_font(port_label, &lv_font_montserrat_14, 0);
        lv_obj_set_style_text_color(port_label, COLOR_SUCCESS, 0);
        lv_obj_set_width(port_label, lv_pct(100));
        open_count++;
      }
    }
    
    if (open_count == 0) {
      lv_obj_t *no_ports_label = lv_label_create(port_column);
      lv_label_set_text(no_ports_label, "No open ports");
      lv_obj_set_style_text_font(no_ports_label, &lv_font_montserrat_14, 0);
      lv_obj_set_style_text_color(no_ports_label, COLOR_TEXT, 0);
      lv_obj_set_width(no_ports_label, lv_pct(100));
    }
  }
  
  // Right column - Ping results
  lv_obj_t *ping_column = lv_obj_create(results_container);
  lv_obj_set_width(ping_column, lv_pct(48));
  lv_obj_set_height(ping_column, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(ping_column, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_bg_opa(ping_column, LV_OPA_0, 0);
  lv_obj_set_style_border_width(ping_column, 0, 0);
  lv_obj_set_style_pad_all(ping_column, 2, 0);
  
  // Show ping results if available
  if (current_ping_stats.packets_sent > 0) {
    // Packets sent/received
    lv_obj_t *packets_label = lv_label_create(ping_column);
    String packets_text = String(current_ping_stats.packets_received) + "/" + 
                         String(current_ping_stats.packets_sent) + " pkts";
    lv_label_set_text(packets_label, packets_text.c_str());
    lv_obj_set_style_text_font(packets_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(packets_label, COLOR_TEXT, 0);
    lv_obj_set_width(packets_label, lv_pct(100));
    
    // Packet loss
    float loss = 100.0 * (1.0 - (float)current_ping_stats.packets_received / current_ping_stats.packets_sent);
    lv_obj_t *loss_label = lv_label_create(ping_column);
    char loss_text[50];
    snprintf(loss_text, sizeof(loss_text), "Loss: %.0f%%", loss);
    lv_label_set_text(loss_label, loss_text);
    lv_obj_set_style_text_font(loss_label, &lv_font_montserrat_14, 0);
    uint32_t loss_color = loss > 20 ? 0xFF0000 : (loss > 5 ? 0xFFFF00 : 0x00FF00);
    lv_obj_set_style_text_color(loss_label, lv_color_hex(loss_color), 0);
    lv_obj_set_width(loss_label, lv_pct(100));
    
    if (current_ping_stats.packets_received > 0) {
      // Min/Max/Avg times
      lv_obj_t *min_label = lv_label_create(ping_column);
      char min_text[50];
      snprintf(min_text, sizeof(min_text), "Min: %.1fms", current_ping_stats.min_ms);
      lv_label_set_text(min_label, min_text);
      lv_obj_set_style_text_font(min_label, &lv_font_montserrat_14, 0);
      lv_obj_set_style_text_color(min_label, COLOR_TEXT, 0);
      lv_obj_set_width(min_label, lv_pct(100));
      
      lv_obj_t *max_label = lv_label_create(ping_column);
      char max_text[50];
      snprintf(max_text, sizeof(max_text), "Max: %.1fms", current_ping_stats.max_ms);
      lv_label_set_text(max_label, max_text);
      lv_obj_set_style_text_font(max_label, &lv_font_montserrat_14, 0);
      lv_obj_set_style_text_color(max_label, COLOR_TEXT, 0);
      lv_obj_set_width(max_label, lv_pct(100));
      
      lv_obj_t *avg_label = lv_label_create(ping_column);
      char avg_text[50];
      snprintf(avg_text, sizeof(avg_text), "Avg: %.1fms", current_ping_stats.avg_ms);
      lv_label_set_text(avg_label, avg_text);
      lv_obj_set_style_text_font(avg_label, &lv_font_montserrat_14, 0);
      lv_obj_set_style_text_color(avg_label, COLOR_TEXT, 0);
      lv_obj_set_width(avg_label, lv_pct(100));
    }
  }
  
  // Load the screen
  Serial.println("[Details] Loading details screen...");
  lv_scr_load(details_screen);
  Serial.println("[Details] Screen loaded successfully!");
}

// Destroy device details screen
void destroyDeviceDetailsScreen() {
  if (!details_screen) return;
  
  // NOTE: No mutex needed - called from LVGL event handler which already has the mutex
  
  // Switch back to main screen
  if (main_screen) {
    lv_scr_load(main_screen);
  }
  
  // Delete the screen
  lv_obj_del(details_screen);
  details_screen = nullptr;
  details_content = nullptr;
  details_port_scan_led = nullptr;
  details_ping_led = nullptr;
  selected_device_index = -1;
  // Don't reset scan_results_for_device - keep results in case we come back
}

void updateOUIProgress(int bytesDownloaded) {
  if (!ouiProgressBar || !ouiProgressLabel) return;
  
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
    return;
  }
  
  int kb = bytesDownloaded / 1024;
  float mb = bytesDownloaded / 1048576.0;
  
  lv_bar_set_value(ouiProgressBar, kb, LV_ANIM_OFF);
  
  char text[64];
  snprintf(text, sizeof(text), "%.1f MB / 6.0 MB", mb);
  lv_label_set_text(ouiProgressLabel, text);
  
  xSemaphoreGive(lvgl_mutex);
}

// Update index building progress
void updateIndexProgress(int entriesIndexed, int totalEntries) {
  if (!ouiProgressBar || !ouiProgressLabel) return;
  
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
    return;
  }
  
  // Show progress as entries out of total
  int progressValue = (entriesIndexed * 100) / totalEntries;
  lv_bar_set_value(ouiProgressBar, progressValue, LV_ANIM_OFF);
  
  char text[64];
  snprintf(text, sizeof(text), "%d / %d vendors", entriesIndexed, totalEntries);
  lv_label_set_text(ouiProgressLabel, text);
  
  xSemaphoreGive(lvgl_mutex);
}

void showOUIResult(bool success) {
  if (!ouiProgressLabel) return;
  
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
    return;
  }
  
  if (success) {
    lv_label_set_text(ouiProgressLabel, "Download Complete!");
    lv_obj_set_style_text_color(ouiProgressLabel, lv_color_hex(0x00FF00), 0);
  } else {
    lv_label_set_text(ouiProgressLabel, "Download Failed!");
    lv_obj_set_style_text_color(ouiProgressLabel, lv_color_hex(0xFF0000), 0);
  }
  
  xSemaphoreGive(lvgl_mutex);
  
  // Show result for 2 seconds so user can see it
  vTaskDelay(pdMS_TO_TICKS(2000));
}

void downloadOUIDatabase() {
  // Match NMEATouch20 pattern: check both flag and mutex existence
  if (!(sdCardReady && sdFileMutex) || !internetConnected) {
    Serial.println("[OUI DB] Cannot download - SD card or internet not available");
    return;
  }
  
  Serial.println("[OUI DB] Downloading IEEE OUI database...");
  
  // Use HTTPS with SSL - we can afford the memory since we reboot after download
  WiFiClientSecure client;
  HTTPClient http;
  
  // Don't verify SSL certificate - saves memory and IEEE cert is trusted
  client.setInsecure();
  
  // Use official IEEE HTTPS URL - most reliable source
  const char* url = "https://standards-oui.ieee.org/oui/oui.txt";
  
  Serial.printf("[OUI DB] Connecting to %s\n", url);
  
  if (!http.begin(client, url)) {
    Serial.println("[OUI DB] ERROR: HTTP begin failed");
    return;
  }
  
  http.setTimeout(60000); // 60 second timeout for large file
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  Serial.println("[OUI DB] Sending HTTP GET request...");
  int code = http.GET();
  
  if (code <= 0) {
    Serial.printf("[OUI DB] ERROR: HTTP request failed, error: %d\n", code);
    http.end();
    return;
  }
  
  if (code != 200 && code != 302) {
    Serial.printf("[OUI DB] ERROR: HTTP response code %d\n", code);
    http.end();
    return;
  }
  
  Serial.printf("[OUI DB] HTTP %d - Starting download\n", code);
  
  // Acquire SD mutex for thread-safe access
  if (xSemaphoreTake(sdFileMutex, pdMS_TO_TICKS(30000)) != pdTRUE) {
    Serial.println("[OUI DB] Failed to acquire SD mutex for download");
    http.end();
    return;
  }
  
  // Delete temporary file if it exists from previous failed attempt
  if (SD.exists(OUI_TEMP_FILE)) {
    Serial.println("[OUI DB] Removing old temporary file...");
    SD.remove(OUI_TEMP_FILE);
  }
  
  // Download to TEMPORARY file - atomic swap on success
  File file = SD.open(OUI_TEMP_FILE, FILE_WRITE);
  if (!file) {
    Serial.println("[OUI DB] ERROR: Failed to create temporary file on SD card");
    Serial.printf("[OUI DB] SD card free space: %llu bytes\n", SD.totalBytes() - SD.usedBytes());
    xSemaphoreGive(sdFileMutex);
    http.end();
    return;
  }
  
  Serial.println("[OUI DB] Temporary file opened for writing");
  
  WiFiClient* stream = http.getStreamPtr();
  
  // Allocate large buffer for fast download - we reboot after so memory doesn't matter
  const size_t BUFFER_SIZE = 4096; // 4KB buffer for fast HTTPS download
  uint8_t* buff = (uint8_t*)malloc(BUFFER_SIZE);
  if (!buff) {
    Serial.println("[OUI DB] ERROR: Failed to allocate download buffer");
    file.close();
    http.end();
    xSemaphoreGive(sdFileMutex);
    return;
  }
  
  int totalBytes = 0;
  int lastReportedKB = 0;
  
  Serial.println("[OUI DB] Streaming data to SD card...");
  
  // Get content length to show accurate progress
  int contentLength = http.getSize();
  Serial.printf("[OUI DB] Content-Length: %d bytes (%.2f MB)\n", contentLength, contentLength / 1048576.0);
  
  // Download with timeout protection
  unsigned long lastDataTime = millis();
  const unsigned long DATA_TIMEOUT = 30000; // 30 seconds without ANY data = failure
  
  // Continue while HTTP is connected OR while data is still available
  while (http.connected() || stream->available()) {
    // Check for available data
    while (stream->available()) {
      size_t size = stream->available();
      int c = stream->readBytes(buff, ((size > BUFFER_SIZE) ? BUFFER_SIZE : size));
      
      if (c > 0) {
        size_t written = file.write(buff, c);
        if (written != c) {
          Serial.println("[OUI DB] ERROR: SD card write failed!");
          goto download_failed;
        }
        totalBytes += c;
        lastDataTime = millis();
        
        // Update progress bar every 50KB
        int currentKB = totalBytes / 1024;
        if (currentKB >= lastReportedKB + 50) {
          Serial.printf("[OUI DB] Downloaded %.1f MB...\n", totalBytes / 1048576.0);
          updateOUIProgress(totalBytes);
          lastReportedKB = currentKB;
        }
        
        // Check if we've received all expected data
        if (contentLength > 0 && totalBytes >= contentLength) {
          Serial.println("[OUI DB] All data received - download complete");
          goto download_complete;
        }
      }
    }
    
    // Check for timeout (no data received for 30 seconds)
    if (millis() - lastDataTime > DATA_TIMEOUT) {
      Serial.println("[OUI DB] ERROR: Download timeout - no data received");
      break;
    }
    
    vTaskDelay(pdMS_TO_TICKS(10)); // Small delay to prevent tight loop
  }
  
download_complete:
download_failed:
  file.close();
  http.end();
  free(buff); // Free the download buffer
  
  Serial.printf("[OUI DB] Download finished: %d bytes (%.2f MB)\n", totalBytes, totalBytes / 1048576.0);
  
  // Validate download size (OUI database should be > 1MB)
  bool downloadSuccess = false;
  if (totalBytes > 1000000) {
    downloadSuccess = true;
    Serial.println("[OUI DB] ========================================");
    Serial.printf("[OUI DB] Download complete: %d bytes (%.2f MB)\n", totalBytes, totalBytes / 1048576.0);
    Serial.println("[OUI DB] ========================================");
  } else {
    Serial.printf("[OUI DB] ERROR: Download incomplete - only %d bytes received\n", totalBytes);
  }
  
  if (downloadSuccess) {
    // Show "tidying up" message
    if (ouiProgressLabel && xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
      lv_label_set_text(ouiProgressLabel, "Tidying up old files...");
      lv_obj_set_style_text_color(ouiProgressLabel, lv_color_hex(0xFFFFFF), 0);
      xSemaphoreGive(lvgl_mutex);
    }
    
    // ATOMIC SWAP with backup and rollback
    bool swapSuccess = false;
    
    // Step 1: Backup existing database if present
    if (SD.exists(OUI_DATABASE_FILE)) {
      // Remove old backup if it exists
      if (SD.exists(OUI_BACKUP_FILE)) {
        SD.remove(OUI_BACKUP_FILE);
      }
      // Rename current database to backup
      if (SD.rename(OUI_DATABASE_FILE, OUI_BACKUP_FILE)) {
        Serial.println("[OUI DB] Existing database backed up");
      } else {
        Serial.println("[OUI DB] ERROR: Failed to backup existing database");
        downloadSuccess = false;
      }
    }
    
    // Step 2: Move new file into place (only if backup succeeded or no file existed)
    if (downloadSuccess && SD.rename(OUI_TEMP_FILE, OUI_DATABASE_FILE)) {
      Serial.println("[OUI DB] New database activated successfully");
      swapSuccess = true;
      
      // Step 3: Clean up backup file on success
      if (SD.exists(OUI_BACKUP_FILE)) {
        SD.remove(OUI_BACKUP_FILE);
        Serial.println("[OUI DB] Backup file removed");
      }
      
      // Save timestamp ONLY on successful download
      File tsFile = SD.open(OUI_TIMESTAMP_FILE, FILE_WRITE);
      if (tsFile) {
        unsigned long currentTime = time(nullptr);
        tsFile.println(currentTime);
        tsFile.close();
        Serial.printf("[OUI DB] Timestamp saved: %lu\n", currentTime);
        
        // Convert to human-readable date
        struct tm timeinfo;
        localtime_r((time_t*)&currentTime, &timeinfo);
        char dateStr[64];
        strftime(dateStr, sizeof(dateStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
        Serial.printf("[OUI DB] Update date: %s\n", dateStr);
      }
      
      // Delete old index file - will be rebuilt
      if (SD.exists(OUI_INDEX_FILE)) {
        Serial.println("[OUI DB] Removing old index file...");
        SD.remove(OUI_INDEX_FILE);
      }
    } else {
      // Step 4: ROLLBACK - Restore backup if swap failed
      Serial.println("[OUI DB] ERROR: Failed to rename temporary file");
      if (SD.exists(OUI_BACKUP_FILE)) {
        if (SD.rename(OUI_BACKUP_FILE, OUI_DATABASE_FILE)) {
          Serial.println("[OUI DB] Backup restored successfully");
        } else {
          Serial.println("[OUI DB] CRITICAL: Failed to restore backup!");
        }
      }
      downloadSuccess = false;
      swapSuccess = false;
    }
  }
  
  // FAILURE: Clean up temporary file
  if (!downloadSuccess) {
    Serial.println("[OUI DB] Cleaning up failed download...");
    if (SD.exists(OUI_TEMP_FILE)) {
      SD.remove(OUI_TEMP_FILE);
    }
    Serial.println("[OUI DB] Download failed - keeping existing database (if any)");
  }
  
  xSemaphoreGive(sdFileMutex);
  
  // Return success/failure status for caller to handle
  if (!downloadSuccess) {
    Serial.println("[OUI DB] DOWNLOAD FAILED - System will continue with existing data");
  }
}

// Structure for efficient memory usage during index building
struct OUIEntry {
  String oui;      // 6 chars
  long position;   // File position
};

// Build SORTED index file for fast binary search lookups
// 
// ===== MEMORY-EFFICIENT CHUNKED MERGE SORT ALGORITHM =====
// 
// CHALLENGE: ESP32 has only ~100KB free RAM, but we need to sort 38,439 entries
// 
// SOLUTION: Chunked Merge Sort
// 1. Read database in chunks of 500 entries (~20KB RAM each)
// 2. Sort each chunk in memory using std::sort
// 3. Write sorted chunks to temporary files: /c0.tmp, /c1.tmp, ... /c76.tmp (77 files)
// 4. Merge chunks pairwise in multiple passes (2-way merge to avoid file descriptor limits):
//    Pass 0: 77 → 39 files (merge pairs, odd one copied)
//    Pass 1: 39 → 20 files
//    Pass 2: 20 → 10 files
//    Pass 3: 10 → 5 files
//    Pass 4: 5 → 3 files
//    Pass 5: 3 → 2 files  
//    Pass 6: 2 → 1 file (final sorted index)
// 5. Final file renamed to /oui.idx
// 
// MEMORY USAGE: Only 20KB RAM throughout entire process (500 entries × 40 bytes)
// TIME: ~60-90 seconds total
// OUTPUT: Sorted index file (~600KB) enabling instant binary search
// 
void buildOUIIndex() {
  Serial.println("[OUI Index] Building SORTED index for binary search (memory-efficient)...");
  
  if (!SD.exists(OUI_DATABASE_FILE)) {
    Serial.println("[OUI Index] ERROR: OUI database not found");
    return;
  }
  
  if (xSemaphoreTake(sdFileMutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
    Serial.println("[OUI Index] Failed to acquire SD mutex");
    return;
  }
  
  // Count entries
  int totalEntries = 0;
  File countFile = SD.open(OUI_DATABASE_FILE, FILE_READ);
  if (countFile) {
    while (countFile.available()) {
      String line = countFile.readStringUntil('\n');
      if (line.indexOf("(base 16)") >= 0) totalEntries++;
      if (totalEntries % 1000 == 0) vTaskDelay(pdMS_TO_TICKS(1));
    }
    countFile.close();
    Serial.printf("[OUI Index] Found %d vendors\n", totalEntries);
  }
  
  createOUIProgressScreen("Building Sorted Index");
  
  // Use chunked processing: 500 entries = ~20KB RAM
  const int CHUNK_SIZE = 500;
  std::vector<OUIEntry> chunk;
  chunk.reserve(CHUNK_SIZE);
  
  File dbFile = SD.open(OUI_DATABASE_FILE, FILE_READ);
  if (!dbFile) {
    Serial.println("[OUI Index] ERROR: Cannot open database");
    xSemaphoreGive(sdFileMutex);
    return;
  }
  
  if (ouiProgressBar && xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    lv_bar_set_range(ouiProgressBar, 0, 100);
    xSemaphoreGive(lvgl_mutex);
  }
  
  int entriesIndexed = 0;
  int chunkNumber = 0;
  
  // Collect entries in chunks, sort each chunk, write to temp files
  while (dbFile.available()) {
    long filePosition = dbFile.position();
    String line = dbFile.readStringUntil('\n');
    
    if (line.indexOf("(base 16)") >= 0) {
      line.trim();
      int base16Idx = line.indexOf("(base 16)");
      if (base16Idx > 0) {
        String oui = line.substring(0, base16Idx);
        oui.trim();
        oui.replace("-", "");
        oui.replace(":", "");
        oui.toUpperCase();
        
        if (oui.length() == 6) {
          OUIEntry entry;
          entry.oui = oui;
          entry.position = filePosition;
          chunk.push_back(entry);
          entriesIndexed++;
          
          // When chunk full, sort and write to temp file
          if (chunk.size() >= CHUNK_SIZE) {
            std::sort(chunk.begin(), chunk.end(), [](const OUIEntry& a, const OUIEntry& b) {
              return a.oui < b.oui;
            });
            
            String tempFile = "/c" + String(chunkNumber++) + ".tmp";
            File cf = SD.open(tempFile.c_str(), FILE_WRITE);
            if (cf) {
              for (const auto& e : chunk) {
                cf.print(e.oui);
                cf.print(":");
                cf.println(e.position);
              }
              cf.close();
            }
            
            chunk.clear();
            if (entriesIndexed % 1000 == 0) {
              Serial.printf("[OUI Index] Sorted %d/%d...\n", entriesIndexed, totalEntries);
              updateIndexProgress(entriesIndexed, totalEntries);
            }
            vTaskDelay(pdMS_TO_TICKS(10));
          }
        }
      }
    }
  }
  
  // Write final chunk
  if (chunk.size() > 0) {
    std::sort(chunk.begin(), chunk.end(), [](const OUIEntry& a, const OUIEntry& b) {
      return a.oui < b.oui;
    });
    String tempFile = "/c" + String(chunkNumber++) + ".tmp";
    File cf = SD.open(tempFile.c_str(), FILE_WRITE);
    if (cf) {
      for (const auto& e : chunk) {
        cf.print(e.oui);
        cf.print(":");
        cf.println(e.position);
      }
      cf.close();
    }
  }
  
  dbFile.close();
  chunk.clear();
  
  // Simple 2-way merge to avoid file descriptor issues
  // Merge pairs of files repeatedly until we have 1 final file
  Serial.printf("[OUI Index] Merging %d sorted chunks...\n", chunkNumber);
  
  int passNumber = 0;
  while (chunkNumber > 1) {
    int newChunkNumber = 0;
    
    // Merge files 2 at a time
    for (int i = 0; i < chunkNumber; i += 2) {
      String outFile = "/m" + String(newChunkNumber++) + ".tmp";
      File output = SD.open(outFile.c_str(), FILE_WRITE);
      
      if (i + 1 < chunkNumber) {
        // Merge two files
        String file1 = "/c" + String(i) + ".tmp";
        String file2 = "/c" + String(i + 1) + ".tmp";
        
        File f1 = SD.open(file1.c_str(), FILE_READ);
        File f2 = SD.open(file2.c_str(), FILE_READ);
        
        OUIEntry entry1, entry2;
        bool has1 = false, has2 = false;
        
        // Read first entries
        if (f1 && f1.available()) {
          String line = f1.readStringUntil('\n');
          line.trim();
          int colon = line.indexOf(':');
          entry1.oui = line.substring(0, colon);
          entry1.position = line.substring(colon + 1).toInt();
          has1 = true;
        }
        if (f2 && f2.available()) {
          String line = f2.readStringUntil('\n');
          line.trim();
          int colon = line.indexOf(':');
          entry2.oui = line.substring(0, colon);
          entry2.position = line.substring(colon + 1).toInt();
          has2 = true;
        }
        
        // Merge
        while (has1 || has2) {
          if (!has2 || (has1 && entry1.oui <= entry2.oui)) {
            output.print(entry1.oui);
            output.print(":");
            output.println(entry1.position);
            
            if (f1.available()) {
              String line = f1.readStringUntil('\n');
              line.trim();
              int colon = line.indexOf(':');
              entry1.oui = line.substring(0, colon);
              entry1.position = line.substring(colon + 1).toInt();
            } else {
              has1 = false;
            }
          } else {
            output.print(entry2.oui);
            output.print(":");
            output.println(entry2.position);
            
            if (f2.available()) {
              String line = f2.readStringUntil('\n');
              line.trim();
              int colon = line.indexOf(':');
              entry2.oui = line.substring(0, colon);
              entry2.position = line.substring(colon + 1).toInt();
            } else {
              has2 = false;
            }
          }
        }
        
        f1.close();
        f2.close();
      } else {
        // Odd file out - just copy it
        String file1 = "/c" + String(i) + ".tmp";
        File f1 = SD.open(file1.c_str(), FILE_READ);
        while (f1.available()) {
          output.println(f1.readStringUntil('\n'));
        }
        f1.close();
      }
      
      output.close();
      vTaskDelay(pdMS_TO_TICKS(10));  // Let system release file descriptors
    }
    
    // Delete old chunks
    for (int i = 0; i < chunkNumber; i++) {
      String oldFile = "/c" + String(i) + ".tmp";
      SD.remove(oldFile.c_str());
    }
    
    // Rename merged files
    for (int i = 0; i < newChunkNumber; i++) {
      String from = "/m" + String(i) + ".tmp";
      String to = "/c" + String(i) + ".tmp";
      SD.rename(from.c_str(), to.c_str());
    }
    
    chunkNumber = newChunkNumber;
    Serial.printf("[OUI Index] Pass %d complete: %d files remaining\n", passNumber++, chunkNumber);
    vTaskDelay(pdMS_TO_TICKS(100));
  }
  
  // Final file is c0.tmp - copy to index file (rename can fail on some SD cards)
  Serial.println("[OUI Index] Writing final index file...");
  if (SD.exists(OUI_INDEX_FILE)) {
    SD.remove(OUI_INDEX_FILE);
  }
  
  File srcFile = SD.open("/c0.tmp", FILE_READ);
  File dstFile = SD.open(OUI_INDEX_FILE, FILE_WRITE);
  
  if (srcFile && dstFile) {
    while (srcFile.available()) {
      dstFile.write(srcFile.read());
    }
    srcFile.close();
    dstFile.close();
    SD.remove("/c0.tmp");
    Serial.println("[OUI Index] Final index file written successfully");
  } else {
    Serial.println("[OUI Index] ERROR: Failed to write final index file!");
    if (srcFile) srcFile.close();
    if (dstFile) dstFile.close();
  }
  
  updateIndexProgress(entriesIndexed, totalEntries);
  xSemaphoreGive(sdFileMutex);
  
  Serial.printf("[OUI Index] Complete! Built sorted index with %d entries\n", entriesIndexed);
}

// Binary search in sorted OUI index file to find MAC vendor
// 
// PRINCIPLE: Instead of reading all 38,439 lines (slow), we use binary search
// which only needs ~15 comparisons to find any entry (O(log n) complexity)
//
// HOW IT WORKS:
// 1. Index file (/oui.idx) contains sorted entries: "ABCDEF:1234567" (OUI:file_position)
// 2. Binary search divides the search space in half each iteration
// 3. Compare middle entry's OUI with target:
//    - If match: return file position → read vendor from OUI.txt at that position
//    - If target is smaller: search left half
//    - If target is larger: search right half
// 4. Repeat until found or search space exhausted
//
// PERFORMANCE: ~15 comparisons vs 38,439 line reads = 2500x faster!
// 
// Returns: File position in OUI.txt where vendor name is located, or -1 if not found
long binarySearchOUIIndex(const String& oui) {
  File idxFile = SD.open(OUI_INDEX_FILE, FILE_READ);
  if (!idxFile) {
    return -1;
  }
  
  // Get file size and estimate line count (each line ~14 bytes: "ABCDEF:1234567\n")
  long fileSize = idxFile.size();
  const int AVG_LINE_SIZE = 14;
  long estimatedLines = fileSize / AVG_LINE_SIZE;
  
  long left = 0;
  long right = estimatedLines - 1;
  long result = -1;
  
  while (left <= right) {
    long mid = left + (right - left) / 2;
    
    // Seek to approximate line position
    long bytePos = mid * AVG_LINE_SIZE;
    idxFile.seek(bytePos);
    
    // Read to next newline to align with line start
    if (bytePos > 0) {
      idxFile.readStringUntil('\n');
    }
    
    // Read the actual line
    if (!idxFile.available()) {
      right = mid - 1;
      continue;
    }
    
    String line = idxFile.readStringUntil('\n');
    line.trim();
    
    if (line.length() < 7) {
      right = mid - 1;
      continue;
    }
    
    String lineOUI = line.substring(0, 6);
    
    if (lineOUI == oui) {
      // Found it! Extract position
      int colonPos = line.indexOf(':');
      if (colonPos > 0) {
        result = line.substring(colonPos + 1).toInt();
      }
      break;
    } else if (lineOUI < oui) {
      left = mid + 1;
    } else {
      right = mid - 1;
    }
    
    // Feed watchdog every few iterations
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  
  idxFile.close();
  return result;
}

// Lookup MAC vendor from SD card OUI database using index for fast lookups
String getMacVendorFromSD(const String& mac) {
  // Check SD card availability
  if (!(sdCardReady && sdFileMutex)) {
    return "";  // Silent failure - SD card not available
  }
  
  // Acquire SD mutex for thread-safe access
  if (xSemaphoreTake(sdFileMutex, pdMS_TO_TICKS(30000)) != pdTRUE) {
    Serial.println("[Vendor SD] Failed to acquire SD mutex after 30s");
    return "";  // Could not acquire mutex
  }
  
  // Extract OUI (first 6 hex digits) - normalize to uppercase, no separators
  String oui = mac.substring(0, 8); // "XX:XX:XX"
  oui.toUpperCase();
  oui.replace(":", "");
  oui.replace("-", "");
  
  if (oui.length() < 6) {
    xSemaphoreGive(sdFileMutex);
    return "";
  }
  
  String vendor = "";
  
  // Use binary search on sorted index (fast: ~15 comparisons for 38K entries)
  if (SD.exists(OUI_INDEX_FILE)) {
    Serial.printf("[Vendor SD] Binary search for %s...\n", oui.c_str());
    
    long filePos = binarySearchOUIIndex(oui);
    
    if (filePos > 0) {
      Serial.printf("[Vendor SD] Found at position: %ld\n", filePos);
      
      // Open database file and seek to position
      File dbFile = SD.open(OUI_DATABASE_FILE, FILE_READ);
      if (dbFile && dbFile.seek(filePos)) {
        String line = dbFile.readStringUntil('\n');
        line.trim();
        
        // Line format: "B827EB     (base 16)		Vendor Name"
        int baseIdx = line.indexOf("(base 16)");
        if (baseIdx > 0) {
          vendor = line.substring(baseIdx + 9); // Skip "(base 16)"
          vendor.trim();
          
          // Store full vendor name (no truncation - details page can display full text)
        }
        dbFile.close();
        xSemaphoreGive(sdFileMutex);
        return vendor;
      }
      if (dbFile) dbFile.close();
    } else {
      // Not found in sorted index - return immediately (likely locally-administered MAC)
      Serial.printf("[Vendor SD] Not found in index\n");
      xSemaphoreGive(sdFileMutex);
      return "";
    }
  } else {
    // Index doesn't exist - something is wrong, don't attempt slow linear search
    Serial.println("[Vendor SD] ERROR: Index file missing - cannot lookup vendors");
    xSemaphoreGive(sdFileMutex);
    return "";
  }
  
  // Should never reach here
  xSemaphoreGive(sdFileMutex); 
  return "";
}

// OUI Update Dialog - prompts user to download database

void ouiUpdateButtonHandler(lv_event_t* e) {
  lv_event_code_t code = lv_event_get_code(e);
  lv_obj_t* btn = (lv_obj_t*)lv_event_get_target(e);
  
  if (code == LV_EVENT_CLICKED) {
    // Check which button was clicked by its label
    lv_obj_t* label = (lv_obj_t*)lv_obj_get_child(btn, 0);
    const char* btn_text = lv_label_get_text(label);
    
    if (strcmp(btn_text, "Update & Reboot") == 0) {
      ouiUpdateUserChoice = true;
    } else {
      ouiUpdateUserChoice = false;
    }
    
    ouiUpdateDialogActive = false;
    lv_msgbox_close(lv_obj_get_parent(btn));
  }
}

void showOUIUpdateDialog() {
  if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
    return;
  }
  
  lv_obj_t *mbox = lv_msgbox_create(NULL);
  lv_msgbox_add_title(mbox, "Database Update Required");
  lv_msgbox_add_text(mbox, "MAC Vendor Database needs updating.\nDownload now (3MB, ~60s)?\n\nDevice will reboot after download.");
  
  lv_obj_t *btn_update = lv_msgbox_add_footer_button(mbox, "Update & Reboot");
  lv_obj_t *btn_skip = lv_msgbox_add_footer_button(mbox, "Skip");
  
  lv_obj_add_event_cb(btn_update, ouiUpdateButtonHandler, LV_EVENT_CLICKED, NULL);
  lv_obj_add_event_cb(btn_skip, ouiUpdateButtonHandler, LV_EVENT_CLICKED, NULL);
  
  ouiUpdateDialogActive = true;
  
  xSemaphoreGive(lvgl_mutex);
}

void handleOUIUpdateFlow() {
  // Reset ONLY user choice - dialog active flag will be set by showOUIUpdateDialog()
  ouiUpdateUserChoice = false;
  
  // Show the dialog (this sets ouiUpdateDialogActive = true)
  Serial.println("[OUI Update] Showing dialog to user...");
  showOUIUpdateDialog();
  
  // Give LVGL time to render the dialog
  delay(500);
  
  // Wait for user response with timeout protection
  Serial.println("[OUI Update] Waiting for user response...");
  unsigned long startTime = millis();
  while (ouiUpdateDialogActive && (millis() - startTime < 60000)) { // 60 second timeout
    delay(100);
  }
  
  // If dialog timed out, default to skip
  if (ouiUpdateDialogActive) {
    Serial.println("[OUI Update] Dialog timeout - defaulting to skip");
    ouiUpdateDialogActive = false;
    ouiUpdateUserChoice = false;
  }
  
  if (ouiUpdateUserChoice) {
    // User chose to update - set flag and reboot
    // The actual download and index building happens on next boot
    Serial.println("[OUI Update] User confirmed - setting pending flag and rebooting...");
    
    // Create pending flag file to trigger update on next boot
    if (sdCardReady && sdFileMutex) {
      if (xSemaphoreTake(sdFileMutex, pdMS_TO_TICKS(2000)) == pdTRUE) {
        File flagFile = SD.open(OUI_PENDING_FILE, FILE_WRITE);
        if (flagFile) {
          flagFile.println("1");
          flagFile.flush();
          flagFile.close();
          Serial.println("[OUI Update] Pending flag created");
        }
        xSemaphoreGive(sdFileMutex);
      }
    }
    
    // Show message and reboot
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
      lv_obj_t *mbox = lv_msgbox_create(NULL);
      lv_msgbox_add_title(mbox, "OUI Database Update");
      lv_msgbox_add_text(mbox, "Device will reboot and update\\nthe OUI database on startup.\\n\\nThis may take 1-2 minutes.");
      lv_msgbox_add_footer_button(mbox, "OK");
      xSemaphoreGive(lvgl_mutex);
    }
    
    delay(2000);
    ESP.restart();
    
    // NEVER REACHED - but prevents compiler warnings
    while(1) { delay(1000); }
  } else {
    Serial.println("[OUI Update] User skipped database update");
  }
  // Only reach here if user skipped - safe to continue normal startup
}

// MAC vendor lookup - returns manufacturer name from OUI
// Also sets vendorFromSD flag in device (searched by MAC)
// 
// FALLBACK BEHAVIOR: Works seamlessly without SD card
// - If SD card present & database available: Uses comprehensive IEEE OUI database (40,000+ vendors)
// - If SD card missing/unavailable: Uses hardcoded database (common vendors only)
// - No errors or crashes if SD card is removed
String getMacVendor(const String& mac, bool* fromSD) {
  // Try SD card database first (returns "" if SD card not available)
  String vendor = getMacVendorFromSD(mac);
  if (vendor.length() > 0) {
    if (fromSD) *fromSD = true;
    Serial.printf("[Vendor] Using SD database vendor for %s: %s\n", mac.c_str(), vendor.c_str());
    return vendor;
  }
  
  // Fall back to hardcoded database (always available)
  if (fromSD) *fromSD = false;
  Serial.printf("[Vendor] Using hardcoded database for %s\n", mac.c_str());
  
  return getMacVendorHardcoded(mac);
}

// Get vendor from hardcoded database only (fast, no SD card access)
String getMacVendorHardcoded(const String& mac) {
  // Extract first 3 bytes (OUI) from MAC address
  String oui = mac.substring(0, 8);  // "XX:XX:XX"
  oui.toUpperCase();
  oui.replace(":", "");  // Remove colons -> "XXXXXX"
  
  // Network Equipment
  if (oui.startsWith("000142") || oui.startsWith("00036B") || oui.startsWith("000A8A") ||
      oui.startsWith("00D0BA") || oui.startsWith("001A2F")) return "Cisco";
  
  if (oui.startsWith("000B82") || oui.startsWith("000F61")) return "Grandstream";
  
  // Sky (UK ISP routers/equipment)
  if (oui.startsWith("04819B") || oui.startsWith("0C8112")) return "Sky UK";
  
  // Additional common vendors
  if (oui.startsWith("50DCE7")) return "Sagemcom";  // Broadband equipment
  if (oui.startsWith("D81399")) return "Google Nest";
  if (oui.startsWith("BC071D")) return "Sercomm";  // Network equipment
  if (oui.startsWith("F0A731")) return "Amazon Lab126";  // Echo/Kindle/Fire devices
  if (oui.startsWith("48E7DA")) return "Amazon Technologies";
  if (oui.startsWith("001C2B")) return "Converged Data Devices";
  if (oui.startsWith("005F67")) return "Hon Hai Precision";  // Foxconn
  if (oui.startsWith("60A4B7")) return "AzureWave";  // WiFi modules
  
  if (oui.startsWith("0CEF15") || oui.startsWith("1C61B4") || oui.startsWith("2C3397") ||
      oui.startsWith("A42BB0") || oui.startsWith("C006C3") || oui.startsWith("D46E0E") ||
      oui.startsWith("F09FC2") || oui.startsWith("50C7BF")) return "TP-Link";
  
  if (oui.startsWith("48D38C") || oui.startsWith("D4A928") || oui.startsWith("48F317")) return "Tapo (TP-Link)";
  
  if (oui.startsWith("001D7E") || oui.startsWith("002590") || oui.startsWith("0050C2") ||
      oui.startsWith("00E04C") || oui.startsWith("84B153") || oui.startsWith("AC9B0A") ||
      oui.startsWith("001A80")) return "Netgear";
  
  if (oui.startsWith("001DD8") || oui.startsWith("002248") || oui.startsWith("00241D") ||
      oui.startsWith("04BD88") || oui.startsWith("FCF528")) return "Ubiquiti";
  
  if (oui.startsWith("000E58") || oui.startsWith("000EA6") || oui.startsWith("001636") ||
      oui.startsWith("002248")) return "D-Link";
  
  // Computers & Mobile
  if (oui.startsWith("00A0C9") || oui.startsWith("001D4F") || oui.startsWith("7C2F80") || 
      oui.startsWith("2CF0A2") || oui.startsWith("00DB70") || oui.startsWith("001124") ||
      oui.startsWith("3451C9") || oui.startsWith("A45E60") || oui.startsWith("D4BE D4")) return "Intel";
  
  // Apple (iPhones, iPads, MacBooks, Apple Watch, etc.) - expanded list
  if (oui.startsWith("000D93") || oui.startsWith("001CF0") || oui.startsWith("E0ACCB") ||
      oui.startsWith("00236C") || oui.startsWith("54AE27") || oui.startsWith("AC87A3") ||
      oui.startsWith("40A6D9") || oui.startsWith("F0DBE2") || oui.startsWith("A4C361") ||
      oui.startsWith("001EC2") || oui.startsWith("002312") || oui.startsWith("002332") ||
      oui.startsWith("0025BC") || oui.startsWith("0026BB") || oui.startsWith("04489A") ||
      oui.startsWith("0C3021") || oui.startsWith("0C3E9F") || oui.startsWith("0C4885") ||
      oui.startsWith("0C74C2") || oui.startsWith("101C0C") || oui.startsWith("1C36BB") ||
      oui.startsWith("1CE62B") || oui.startsWith("20768F") || oui.startsWith("24A074") ||
      oui.startsWith("24A2E1") || oui.startsWith("28A02B") || oui.startsWith("28E02C") ||
      oui.startsWith("28E14C") || oui.startsWith("2CF0A2") || oui.startsWith("30636B") ||
      oui.startsWith("3451C9") || oui.startsWith("38C986") || oui.startsWith("3C0754") ||
      oui.startsWith("40831D") || oui.startsWith("40D32D") || oui.startsWith("44D884") ||
      oui.startsWith("483B38") || oui.startsWith("48D705") || oui.startsWith("4C7C5F") ||
      oui.startsWith("5433CB") || oui.startsWith("5CF938") || oui.startsWith("609217") ||
      oui.startsWith("64200C") || oui.startsWith("64B9E8") || oui.startsWith("68AE20") ||
      oui.startsWith("6C3E6D") || oui.startsWith("6C94F8") || oui.startsWith("6CAB31") ||
      oui.startsWith("70CD60") || oui.startsWith("70E72C") || oui.startsWith("7831C1") ||
      oui.startsWith("7C04D0") || oui.startsWith("7C6D62") || oui.startsWith("7CF05F") ||
      oui.startsWith("8425DB") || oui.startsWith("848506") || oui.startsWith("8489AD") ||
      oui.startsWith("88E87F") || oui.startsWith("8C006D") || oui.startsWith("8C2DAA") ||
      oui.startsWith("8C7C92") || oui.startsWith("8CF5A3") || oui.startsWith("90840D") ||
      oui.startsWith("9803D8") || oui.startsWith("9C207B") || oui.startsWith("9CE33F") ||
      oui.startsWith("A43135") || oui.startsWith("A49A58") || oui.startsWith("A82066") ||
      oui.startsWith("AC293A") || oui.startsWith("ACE4B5") || oui.startsWith("B065BD") ||
      oui.startsWith("B0CA68") || oui.startsWith("B418D1") || oui.startsWith("B853AC") ||
      oui.startsWith("B8782E") || oui.startsWith("BC3BAF") || oui.startsWith("BC52B7") ||
      oui.startsWith("BC9FEF") || oui.startsWith("C06394") || oui.startsWith("C0847A") ||
      oui.startsWith("C42C03") || oui.startsWith("C82A14") || oui.startsWith("CC25EF") ||
      oui.startsWith("D023DB") || oui.startsWith("D0E140") || oui.startsWith("D49A20") ||
      oui.startsWith("D81D72") || oui.startsWith("D8A25E") || oui.startsWith("DC2B2A") ||
      oui.startsWith("DC3714") || oui.startsWith("DC86D8") || oui.startsWith("E0B52D") ||
      oui.startsWith("E4C63D") || oui.startsWith("E498D6") || oui.startsWith("E80688") ||
      oui.startsWith("E8802E") || oui.startsWith("EC358B") || oui.startsWith("F0D1A9") ||
      oui.startsWith("F41BA1") || oui.startsWith("F437B7") || oui.startsWith("F45C89") ||
      oui.startsWith("F82793") || oui.startsWith("F86214") || oui.startsWith("FC253F")) return "Apple";
  
  if (oui.startsWith("001E58") || oui.startsWith("78E400") || oui.startsWith("20F478") ||
      oui.startsWith("6C198F") || oui.startsWith("7CD1C3") || oui.startsWith("34CE00") ||
      oui.startsWith("E4B021") || oui.startsWith("C48508") || oui.startsWith("18D6C7")) return "Samsung";
  
  if (oui.startsWith("C40415") || oui.startsWith("74E543") || oui.startsWith("84A134") ||
      oui.startsWith("683E34") || oui.startsWith("3C5A37") || oui.startsWith("F4F5D8")) return "Google";
  
  if (oui.startsWith("001E8C") || oui.startsWith("0050F2") || oui.startsWith("001AA0") ||
      oui.startsWith("7C1E52") || oui.startsWith("0019D2")) return "Microsoft";
  
  if (oui.startsWith("2C1F23") || oui.startsWith("10BF48") || oui.startsWith("206E9C") ||
      oui.startsWith("5C96A2") || oui.startsWith("24E853") || oui.startsWith("805B65") ||
      oui.startsWith("A0E7D9") || oui.startsWith("F8DA0C")) return "LG Electronics";
  
  if (oui.startsWith("001A6B") || oui.startsWith("DC9B9C") || oui.startsWith("001A45") ||
      oui.startsWith("708BCD")) return "Asustek";
  
  if (oui.startsWith("001C23") || oui.startsWith("002191") || oui.startsWith("001CF6")) return "Hon Hai/Foxconn";
  
  if (oui.startsWith("30E37A") || oui.startsWith("F8A2D6") || oui.startsWith("54B80A")) return "Huawei";
  
  if (oui.startsWith("D48564") || oui.startsWith("7CEF96") || oui.startsWith("24DBEA")) return "Xiaomi";
  
  if (oui.startsWith("C83DD4") || oui.startsWith("14F42A") || oui.startsWith("B0D59D")) return "OnePlus";
  
  // TV & Entertainment
  if (oui.startsWith("001C62") || oui.startsWith("84C0EF") || oui.startsWith("141F78") ||
      oui.startsWith("0024BE") || oui.startsWith("E00270") || oui.startsWith("001E45")) return "Sony";
  
  if (oui.startsWith("000CE9") || oui.startsWith("E0B520") || oui.startsWith("F8A9D0") ||
      oui.startsWith("68B9D3")) return "Hisense";
  
  if (oui.startsWith("001DE5") || oui.startsWith("30A8DB") || oui.startsWith("C8191F") ||
      oui.startsWith("D8F889")) return "TCL";
  
  if (oui.startsWith("002719") || oui.startsWith("28EDD1") || oui.startsWith("001F1F") ||
      oui.startsWith("08ED02")) return "Vizio";
  
  if (oui.startsWith("ECF073") || oui.startsWith("787B8A") || oui.startsWith("088E64")) return "Amazon (Echo/Fire)";
  
  if (oui.startsWith("D4A67C") || oui.startsWith("001120") || oui.startsWith("D00057")) return "Roku";
  
  // IoT & Smart Devices
  if (oui.startsWith("B827EB") || oui.startsWith("DCA632") || oui.startsWith("E45F01") ||
      oui.startsWith("DC443D") || oui.startsWith("B827EB")) return "Raspberry Pi";
  
  if (oui.startsWith("001B63") || oui.startsWith("1062EB") || oui.startsWith("B0B98E") ||
      oui.startsWith("A0D795") || oui.startsWith("240AC4") || oui.startsWith("8C4B14")) return "Espressif (ESP32)";
  
  if (oui.startsWith("306893") || oui.startsWith("482AB8") || oui.startsWith("D89EF3")) return "Shenzhen Jingxun";
  
  if (oui.startsWith("0017EB") || oui.startsWith("000B57") || oui.startsWith("001788")) return "Philips Hue";
  
  if (oui.startsWith("34CE00") || oui.startsWith("6464E8")) return "Sonoff";
  
  if (oui.startsWith("B4E62D") || oui.startsWith("D8F15B") || oui.startsWith("6C5AB0")) return "Ring";
  
  if (oui.startsWith("5CCF7F") || oui.startsWith("F0B429") || oui.startsWith("70EE50")) return "Honeywell";
  
  if (oui.startsWith("18B430") || oui.startsWith("000475") || oui.startsWith("001D79")) return "Nest";
  
  // Printers
  if (oui.startsWith("001CF1") || oui.startsWith("009027") || oui.startsWith("00095B") ||
      oui.startsWith("001B38") || oui.startsWith("D0BF9C") || oui.startsWith("B0 5ADA")) return "HP";
  
  if (oui.startsWith("000085") || oui.startsWith("001120") || oui.startsWith("002536")) return "Epson";
  
  if (oui.startsWith("002522") || oui.startsWith("308D99") || oui.startsWith("00E02C")) return "Canon";
  
  if (oui.startsWith("00A0D1") || oui.startsWith("002308") || oui.startsWith("00248C")) return "Brother";
  
  // Virtualization
  if (oui.startsWith("000C29") || oui.startsWith("005056") || oui.startsWith("000569")) return "VMware";
  
  if (oui.startsWith("080027") || oui.startsWith("0A0027")) return "VirtualBox";
  
  if (oui.startsWith("00155D") || oui.startsWith("001DD8")) return "Hyper-V";
  
  // Gaming
  if (oui.startsWith("000D3A") || oui.startsWith("001EA9") || oui.startsWith("001F3C")) return "Sony PlayStation";
  
  if (oui.startsWith("0009BF") || oui.startsWith("001B EA") || oui.startsWith("7CBB8A")) return "Nintendo";
  
  if (oui.startsWith("20D390") || oui.startsWith("B0D5CC") || oui.startsWith("28107B")) return "Microsoft Xbox";

  
  return "";  // Unknown vendor
}

// Query UPnP/SSDP for device discovery (many devices advertise friendly names)
String queryUPnP(const IPAddress& ip) {
  Serial.printf("[UPnP] Querying %s...\n", ip.toString().c_str());
  
  // Send SSDP M-SEARCH to discover UPnP devices
  WiFiUDP udp;
  if (!udp.begin(0)) {
    Serial.println("[UPnP] Failed to start UDP");
    return "";
  }
  
  const char* msearch = 
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n";
  
  // Send to specific IP (not multicast) on SSDP port
  udp.beginPacket(ip, 1900);
  udp.write((const uint8_t*)msearch, strlen(msearch));
  udp.endPacket();
  
  // Wait for response
  TickType_t startTick = xTaskGetTickCount();
  while ((xTaskGetTickCount() - startTick) < pdMS_TO_TICKS(200)) {
    int packetSize = udp.parsePacket();
    if (packetSize > 0) {
      char response[1024];
      int len = udp.read(response, sizeof(response) - 1);
      response[len] = '\0';
      
      // Look for LOCATION header to get device description URL
      char* location = strstr(response, "LOCATION: ");
      if (location) {
        location += 10; // Skip "LOCATION: "
        char* end = strstr(location, "\r\n");
        if (end) {
          String url = String(location).substring(0, end - location);
          Serial.printf("[UPnP] Found device at: %s\n", url.c_str());
          
          // UPnP device found, but we don't parse the XML for friendly name
          // This isn't a real DNS hostname, so don't return it
          // (It would show as yellow but wouldn't be resolvable on the network)
          // TODO: Implement XML parsing if we want to show UPnP device names
          udp.stop();
          return "";  // Don't return placeholder name
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(50));
  }
  
  Serial.printf("[UPnP] No response from %s\n", ip.toString().c_str());
  udp.stop();
  return "";
}

// Query reverse DNS (PTR record) - checks router's DNS cache for DHCP hostnames
String queryReverseDNS(const IPAddress& ip) {
  Serial.printf("[ReverseDNS] Querying %s...\n", ip.toString().c_str());
  
  WiFiUDP udp;
  if (!udp.begin(0)) {
    Serial.println("[ReverseDNS] Failed to start UDP");
    return "";
  }
  
  // Build reverse DNS query (PTR record for in-addr.arpa)
  // e.g., 192.168.4.55 -> 55.4.168.192.in-addr.arpa
  uint8_t query[512];
  int idx = 0;
  
  // Transaction ID
  query[idx++] = random(256);
  query[idx++] = random(256);
  
  // Flags: Standard query, recursion desired
  query[idx++] = 0x01;
  query[idx++] = 0x00;
  
  // Questions: 1
  query[idx++] = 0x00;
  query[idx++] = 0x01;
  
  // Answer RRs: 0
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  
  // Authority RRs: 0
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  
  // Additional RRs: 0
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  
  // Build QNAME: reverse IP octets + ".in-addr.arpa"
  char octet[4];
  for (int i = 3; i >= 0; i--) {
    sprintf(octet, "%d", ip[i]);
    query[idx++] = strlen(octet);
    for (size_t j = 0; j < strlen(octet); j++) {
      query[idx++] = octet[j];
    }
  }
  
  // "in-addr"
  query[idx++] = 7;
  memcpy(&query[idx], "in-addr", 7);
  idx += 7;
  
  // "arpa"
  query[idx++] = 4;
  memcpy(&query[idx], "arpa", 4);
  idx += 4;
  
  // Null terminator
  query[idx++] = 0;
  
  // Type: PTR (12)
  query[idx++] = 0x00;
  query[idx++] = 0x0C;
  
  // Class: IN (1)
  query[idx++] = 0x00;
  query[idx++] = 0x01;
  
  // Send query to DNS server (try configured DNS, fall back to gateway)
  IPAddress dnsServer = WiFi.dnsIP();
  if (dnsServer == IPAddress(0, 0, 0, 0)) {
    dnsServer = WiFi.gatewayIP();  // Fall back to gateway
  }
  
  Serial.printf("[ReverseDNS] Using DNS server: %s\n", dnsServer.toString().c_str());
  udp.beginPacket(dnsServer, 53);
  udp.write(query, idx);
  udp.endPacket();
  
  // Wait for response
  TickType_t startTick = xTaskGetTickCount();
  while ((xTaskGetTickCount() - startTick) < pdMS_TO_TICKS(200)) {
    int packetSize = udp.parsePacket();
    if (packetSize > 12) {
      uint8_t response[512];
      int len = udp.read(response, sizeof(response));
      
      // Check if response is valid and has answers
      if (len > 12) {
        int answerCount = (response[6] << 8) | response[7];
        if (answerCount > 0) {
          // Skip header (12 bytes) and question section
          int pos = 12;
          
          // Skip question section (QNAME + QTYPE + QCLASS)
          while (pos < len && response[pos] != 0) {
            if ((response[pos] & 0xC0) == 0xC0) {
              pos += 2;  // Compressed name pointer
              break;
            }
            pos += response[pos] + 1;
          }
          pos += 5;  // Skip null terminator + QTYPE + QCLASS
          
          // Parse answer section
          if (pos + 12 < len) {
            // Skip NAME field (might be compressed pointer)
            if ((response[pos] & 0xC0) == 0xC0) {
              pos += 2;
            } else {
              while (pos < len && response[pos] != 0) {
                pos += response[pos] + 1;
              }
              pos++;
            }
            
            // TYPE (2 bytes) + CLASS (2 bytes) + TTL (4 bytes) + RDLENGTH (2 bytes)
            if (pos + 10 < len) {
              uint16_t rdlength = (response[pos + 8] << 8) | response[pos + 9];
              pos += 10;
              
              // Parse PTR RDATA (domain name)
              if (pos + rdlength <= len) {
                String hostname = "";
                int endPos = pos + rdlength;
                while (pos < endPos && response[pos] != 0) {
                  if ((response[pos] & 0xC0) == 0xC0) {
                    // Compressed pointer - not handling for simplicity
                    break;
                  }
                  int labelLen = response[pos++];
                  for (int i = 0; i < labelLen && pos < endPos; i++) {
                    if (response[pos] >= 0x20 && response[pos] <= 0x7E) {
                      hostname += (char)response[pos];
                    }
                    pos++;
                  }
                  if (pos < endPos && response[pos] != 0) {
                    hostname += ".";
                  }
                }
                
                // Remove .local or domain suffix if present
                hostname.replace(".local", "");
                int dotPos = hostname.indexOf('.');
                if (dotPos > 0) {
                  hostname = hostname.substring(0, dotPos);  // Keep only hostname part
                }
                
                // Filter out invalid/placeholder names
                if (hostname.length() > 0 && hostname != "UNKNOWN" && hostname != "Unknown" && hostname != "unknown") {
                  Serial.printf("[ReverseDNS] Found: %s\n", hostname.c_str());
                  udp.stop();
                  return hostname;
                }
              }
            }
          }
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  
  Serial.printf("[ReverseDNS] No response from %s\n", ip.toString().c_str());
  udp.stop();
  return "";
}

// Query LLMNR (Link-Local Multicast Name Resolution) - Modern Windows name resolution
String queryLLMNR(const IPAddress& ip) {
  Serial.printf("[LLMNR] Querying %s...\n", ip.toString().c_str());
  
  WiFiUDP udp;
  if (!udp.begin(0)) {
    Serial.println("[LLMNR] Failed to start UDP");
    return "";
  }
  
  // Build LLMNR query (similar to DNS but multicast)
  uint8_t query[512];
  int idx = 0;
  
  // Transaction ID
  query[idx++] = random(256);
  query[idx++] = random(256);
  
  // Flags: Standard query
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  
  // Questions: 1
  query[idx++] = 0x00;
  query[idx++] = 0x01;
  
  // Answer/Authority/Additional: 0
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  query[idx++] = 0x00;
  
  // Build reverse lookup name (x.x.x.x.in-addr.arpa)
  char octet[4];
  for (int i = 3; i >= 0; i--) {
    sprintf(octet, "%d", ip[i]);
    query[idx++] = strlen(octet);
    for (size_t j = 0; j < strlen(octet); j++) {
      query[idx++] = octet[j];
    }
  }
  
  query[idx++] = 7;
  memcpy(&query[idx], "in-addr", 7);
  idx += 7;
  
  query[idx++] = 4;
  memcpy(&query[idx], "arpa", 4);
  idx += 4;
  
  query[idx++] = 0;  // Null terminator
  
  // Type: PTR (12)
  query[idx++] = 0x00;
  query[idx++] = 0x0C;
  
  // Class: IN (1)
  query[idx++] = 0x00;
  query[idx++] = 0x01;
  
  // Send to LLMNR multicast address
  IPAddress llmnrMulticast(224, 0, 0, 252);
  udp.beginPacket(llmnrMulticast, 5355);  // LLMNR port
  udp.write(query, idx);
  udp.endPacket();
  
  // Also send unicast to specific IP
  udp.beginPacket(ip, 5355);
  udp.write(query, idx);
  udp.endPacket();
  
  // Wait for response
  TickType_t startTick = xTaskGetTickCount();
  while ((xTaskGetTickCount() - startTick) < pdMS_TO_TICKS(150)) {
    int packetSize = udp.parsePacket();
    if (packetSize > 12) {
      uint8_t response[512];
      int len = udp.read(response, sizeof(response));
      
      if (len > 12) {
        int answerCount = (response[6] << 8) | response[7];
        if (answerCount > 0) {
          // Parse the answer (simplified - similar to DNS PTR parsing)
          // This would need proper implementation
          Serial.println("[LLMNR] Got response (parsing not implemented)");
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  
  Serial.printf("[LLMNR] No response from %s\n", ip.toString().c_str());
  udp.stop();
  return "";
}

// Resolve hostname using multiple methods in priority order
// Stops as soon as a valid hostname is found
String resolveHostname(const String& ipStr) {
  IPAddress ip;
  if (!ip.fromString(ipStr)) {
    return "";
  }
  
  Serial.printf("[Hostname] Resolving %s...\n", ipStr.c_str());
  String name;
  
  // Priority 1: Reverse DNS (router's DNS cache - most reliable, fast)
  name = queryReverseDNS(ip);
  if (name.length() > 0) {
    Serial.printf("[Hostname] ReverseDNS resolved: %s -> %s\n", ipStr.c_str(), name.c_str());
    return name;  // STOP - we have a good hostname
  }
  
  // Priority 2: UPnP/SSDP (IoT devices, printers, media servers)
  name = queryUPnP(ip);
  if (name.length() > 0) {
    Serial.printf("[Hostname] UPnP resolved: %s -> %s\n", ipStr.c_str(), name.c_str());
    return name;  // STOP - we have a good hostname
  }
  
  // mDNS and NetBIOS removed - not finding any devices on this network
  
  Serial.printf("[Hostname] No hostname found for %s (will use MAC vendor as fallback)\n", ipStr.c_str());
  return "";  // No hostname found - caller will use MAC vendor lookup
}

// SD Card Check Task - monitors SD card presence (matches NMEATouch20)
void sdCardCheckTask(void *parameter) {
  Serial.println("[SDCardTask] Task started");
  
  while (1) {
    // Only check if we can quickly acquire the mutex (non-blocking check)
    // This prevents interfering with other SD operations
    if (sdFileMutex && xSemaphoreTake(sdFileMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
      // Quick check: just verify card type (very fast)
      // This also acts as a "keep-alive" to prevent the card from sleeping
      uint8_t cardType = SD.cardType();
      bool cardPresent = (cardType != CARD_NONE);
      
      if (cardPresent) {
        if (!sdCardReady) {
          Serial.println("[SD] Card detected - marking ready");
        }
        sdCardReady = true;
      } else {
        if (sdCardReady) {
          Serial.println("[SD] Card removed or failed - marking not ready");
        }
        sdCardReady = false;
      }
      
      xSemaphoreGive(sdFileMutex);
    }
    // If we can't get the mutex, skip this check - another operation is using the SD card
    
    vTaskDelay(pdMS_TO_TICKS(2000)); // Check every 2 seconds
  }
}

// DHCP Snooping task - passively listens for DHCP packets to extract hostnames
void DHCPSnoopTask(void *parameter) {
  Serial.println("[DHCPSnoop] Task started");
  
  // Wait for WiFi to be connected before starting
  while (!wifiConnected) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
  
  WiFiUDP udp;
  // Try port 68 (DHCP client port) - this is where DHCP replies come
  // We'll see broadcasts and our own DHCP traffic
  if (!udp.begin(68)) {  
    Serial.println("[DHCPSnoop] Failed to bind to port 68, trying port 67...");
    if (!udp.begin(67)) {  // Try DHCP server port as fallback
      Serial.println("[DHCPSnoop] Failed to bind to any DHCP port - task disabled");
      vTaskDelete(NULL);
      return;
    }
    Serial.println("[DHCPSnoop] Listening on port 67");
  } else {
    Serial.println("[DHCPSnoop] Listening for DHCP packets on port 68");
  }
  
  while (1) {
    int packetSize = udp.parsePacket();
    if (packetSize > 240) {  // DHCP minimum size
      uint8_t packet[512];
      int len = udp.read(packet, sizeof(packet));
      
      // DHCP packet structure:
      // 0: Message type (1=request, 2=reply)
      // 4-7: Transaction ID
      // 28-43: Client MAC address (16 bytes, first 6 used)
      // 44-235: Server/client addresses
      // 236-239: Magic cookie (0x63825363)
      // 240+: Options
      
      if (len >= 240) {
        // Verify DHCP magic cookie
        if (packet[236] == 0x63 && packet[237] == 0x82 && 
            packet[238] == 0x53 && packet[239] == 0x63) {
          
          // Extract client MAC
          char clientMac[18];
          snprintf(clientMac, sizeof(clientMac), "%02X:%02X:%02X:%02X:%02X:%02X",
                   packet[28], packet[29], packet[30], packet[31], packet[32], packet[33]);
          
          // Parse DHCP options for hostname (option 12)
          int pos = 240;
          String hostname = "";
          IPAddress clientIP(0, 0, 0, 0);
          
          while (pos < len - 2) {
            uint8_t option = packet[pos++];
            if (option == 0xFF) break;  // End option
            if (option == 0x00) continue;  // Pad option
            
            uint8_t optLen = packet[pos++];
            if (pos + optLen > len) break;
            
            // Option 12: Hostname
            if (option == 12 && optLen > 0) {
              hostname = "";
              for (int i = 0; i < optLen && i < 63; i++) {
                if (packet[pos + i] >= 0x20 && packet[pos + i] <= 0x7E) {
                  hostname += (char)packet[pos + i];
                }
              }
            }
            
            // Option 50: Requested IP
            if (option == 50 && optLen == 4) {
              clientIP = IPAddress(packet[pos], packet[pos+1], packet[pos+2], packet[pos+3]);
            }
            
            pos += optLen;
          }
          
          // If we got a hostname, update or add the device
          if (hostname.length() > 0) {
            Serial.printf("[DHCPSnoop] Captured: MAC=%s, Hostname=%s", clientMac, hostname.c_str());
            if (clientIP != IPAddress(0, 0, 0, 0)) {
              Serial.printf(", IP=%s", clientIP.toString().c_str());
            }
            Serial.println();
            
            // Update or add device in list
            if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
              bool found = false;
              for (size_t i = 0; i < networkDevices.size(); i++) {
                if (networkDevices[i].mac == String(clientMac)) {
                  found = true;
                  // Update existing device's IP if provided
                  if (clientIP != IPAddress(0, 0, 0, 0)) {
                    networkDevices[i].ip = clientIP.toString();
                  }
                  
                  // DHCP is authoritative - update if hostname changed or not yet set from DHCP
                  if (networkDevices[i].name != hostname) {
                    networkDevices[i].name = hostname;
                    networkDevices[i].hostnameResolved = true;
                    networkDevices[i].fromDHCP = true;  // Mark as authoritative DHCP source
                    networkDevices[i].lastSeen = millis();
                    deviceListChanged = true;
                    Serial.printf("[DHCPSnoop] Updated hostname (DHCP authoritative): %s -> %s\n", clientMac, hostname.c_str());
                  } else if (networkDevices[i].fromDHCP) {
                    // Already have this exact DHCP hostname - just refresh timestamp
                    networkDevices[i].lastSeen = millis();
                    Serial.printf("[DHCPSnoop] Already have DHCP hostname for %s: %s\n", clientMac, hostname.c_str());
                  } else {
                    // Had query-based hostname, now replacing with DHCP (authoritative)
                    networkDevices[i].hostnameResolved = true;
                    networkDevices[i].fromDHCP = true;
                    networkDevices[i].lastSeen = millis();
                    deviceListChanged = true;
                    Serial.printf("[DHCPSnoop] Replaced query hostname with DHCP: %s -> %s\n", clientMac, hostname.c_str());
                  }
                  break;
                }
              }
              
              // If device not found, ADD it as new device with DHCP hostname
              if (!found && clientIP != IPAddress(0, 0, 0, 0)) {
                NetworkDevice newDev;
                newDev.mac = String(clientMac);
                newDev.ip = clientIP.toString();
                newDev.name = hostname;
                newDev.hostnameResolved = true;
                newDev.fromDHCP = true;  // DHCP is authoritative
                newDev.vendor = getMacVendorHardcoded(newDev.mac);  // Instant hardcoded lookup
                newDev.vendorResolved = true;
                newDev.vendorFromSD = false;
                newDev.vendorSDAttempted = false;
                newDev.rssi = 0;
                newDev.lastSeen = millis();
                
                networkDevices.push_back(newDev);
                deviceListChanged = true;
                Serial.printf("[DHCPSnoop] Added NEW device via DHCP: %s - %s - %s\n", 
                             newDev.ip.c_str(), newDev.mac.c_str(), hostname.c_str());
              }
              
              xSemaphoreGive(devices_mutex);
            }
          }
        }
      }
    }
    
    vTaskDelay(pdMS_TO_TICKS(10));  // Small delay to yield
  }
}

// Background task for hostname resolution - works completely independently
// We run MULTIPLE instances of this task in parallel for faster resolution
void HostnameResolverTask(void *parameter) {
  int taskId = (int)parameter;  // Each task gets a unique ID
  Serial.printf("[HostnameResolver-%d] Task started\n", taskId);
  
  while (1) {
    HostnameRequest req;
    
    // Wait for a hostname resolution request from the queue
    if (xQueueReceive(hostname_queue, &req, pdMS_TO_TICKS(1000)) == pdTRUE) {
      
      // Check if device already has a hostname - skip resolution if so
      bool alreadyResolved = false;
      if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (size_t i = 0; i < networkDevices.size(); i++) {
          if (networkDevices[i].mac == String(req.mac)) {
            // Skip if hostname exists AND either: from DHCP (authoritative) OR already resolved by query
            if (networkDevices[i].name.length() > 0) {
              if (networkDevices[i].fromDHCP) {
                alreadyResolved = true;
                Serial.printf("[HostnameResolver] Skipping %s - has DHCP hostname (authoritative): %s\n", req.ip, networkDevices[i].name.c_str());
              } else if (networkDevices[i].hostnameResolved) {
                alreadyResolved = true;
                Serial.printf("[HostnameResolver] Skipping %s - already has hostname: %s\n", req.ip, networkDevices[i].name.c_str());
              }
              break;
            }
          }
        }
        xSemaphoreGive(devices_mutex);
      }
      
      if (alreadyResolved) {
        vTaskDelay(pdMS_TO_TICKS(10));  // Yield CPU before skipping to next request
        continue;  // Skip to next request
      }
      
      Serial.printf("[HostnameResolver-%d] Resolving %s (MAC: %s)\n", taskId, req.ip, req.mac);
      
      // Do the actual resolution (stops at first successful method)
      String hostname = resolveHostname(String(req.ip));
      
      // Protect access to networkDevices vector
      if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        if (hostname.length() > 0) {
          // Find the device in the list and update it
          bool deviceFound = false;
          for (size_t i = 0; i < networkDevices.size(); i++) {
            if (networkDevices[i].mac == String(req.mac)) {
              deviceFound = true;
              // Only update if not from DHCP (DHCP is authoritative)
              if (!networkDevices[i].fromDHCP) {
                networkDevices[i].name = hostname;
                networkDevices[i].hostnameResolved = true;
                networkDevices[i].fromDHCP = false;  // Mark as query-based, not DHCP
                deviceListChanged = true;
                Serial.printf("[HostnameResolver-%d] SUCCESS: %s (%s) -> %s\n", taskId, req.ip, req.mac, hostname.c_str());
              } else {
                Serial.printf("[HostnameResolver-%d] Skipping update - %s has DHCP hostname (authoritative): %s\n", taskId, req.ip, networkDevices[i].name.c_str());
              }
              break;
            }
          }
          if (!deviceFound) {
            Serial.printf("[HostnameResolver-%d] WARNING: Device %s (MAC: %s) not found in list - hostname '%s' not saved\n", taskId, req.ip, req.mac, hostname.c_str());
          }
        } else {
          // No hostname found - mark as resolved anyway to prevent endless re-queuing
          for (size_t i = 0; i < networkDevices.size(); i++) {
            if (networkDevices[i].mac == String(req.mac)) {
              networkDevices[i].hostnameResolved = true;  // Stop re-queuing
              deviceListChanged = true;
              break;
            }
          }
          Serial.printf("[HostnameResolver-%d] No hostname found for %s (displaying with MAC vendor)\n", taskId, req.ip);
        }
        xSemaphoreGive(devices_mutex);
      } else {
        Serial.printf("[HostnameResolver-%d] Failed to acquire devices_mutex for %s\n", taskId, req.ip);
      }
    }
  }
}

// LVGL task
void LVGLTask(void *parameter)
{
  const TickType_t xDelay = pdMS_TO_TICKS(16);  // ~60 FPS
  TickType_t lastWatchdogFeed = xTaskGetTickCount();
  
  while (1)
  {
    lv_tick_inc(16);
    
    // Feed watchdog every second to prevent timeout
    if ((xTaskGetTickCount() - lastWatchdogFeed) > pdMS_TO_TICKS(1000)) {
      lastWatchdogFeed = xTaskGetTickCount();
    }
    
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
    
      // Handle scan indicator blinking (network analyzer screen)
      if (scan_indicator) {
      if (scanInProgress) {
        unsigned long currentTime = millis();
        static unsigned long lastBlinkTime = 0;
        if (currentTime - lastBlinkTime >= LED_BLINK_INTERVAL_MS) {
          lastBlinkTime = currentTime;
          static bool blinkState = false;
          blinkState = !blinkState;
          lv_obj_set_style_bg_color(scan_indicator, 
            blinkState ? COLOR_INDICATOR_ON : COLOR_INDICATOR_OFF, 0);
        }
      } else {
        // Gray when not scanning
        lv_obj_set_style_bg_color(scan_indicator, COLOR_INDICATOR_OFF, 0);
      }
    }
    
    // Handle splash screen loading indicator blinking
    if (splash_loading_indicator) {
      unsigned long currentTime = millis();
      static unsigned long splashBlinkTime = 0;
      if (currentTime - splashBlinkTime >= LED_BLINK_INTERVAL_MS) {
        splashBlinkTime = currentTime;
        static bool splashBlinkState = false;
        splashBlinkState = !splashBlinkState;
        lv_obj_set_style_bg_color(splash_loading_indicator, 
          splashBlinkState ? COLOR_INDICATOR_ON : COLOR_INDICATOR_OFF, 0);
      }
    }
    
    // Handle WiFi scan indicator blinking (WiFi setup screen)
    if (wifi_scan_indicator) {
      if (wifi_scanning) {
        unsigned long currentTime = millis();
        static unsigned long wifiBlinkTime = 0;
        if (currentTime - wifiBlinkTime >= LED_BLINK_INTERVAL_MS) {
          wifiBlinkTime = currentTime;
          static bool wifiBlinkState = false;
          wifiBlinkState = !wifiBlinkState;
          lv_obj_set_style_bg_color(wifi_scan_indicator, 
            wifiBlinkState ? COLOR_INDICATOR_ON : COLOR_INDICATOR_OFF, 0);
        }
      } else {
        // Gray when not scanning
        lv_obj_set_style_bg_color(wifi_scan_indicator, COLOR_INDICATOR_OFF, 0);
      }
    }
    
    // Handle device details screen scan/ping indicator blinking (individual LEDs at 3Hz)
    if (details_port_scan_led || details_ping_led) {
      unsigned long currentTime = millis();
      static unsigned long detailsBlinkTime = 0;
      static bool detailsBlinkState = false;
      const unsigned long FAST_BLINK_INTERVAL = 167;  // ~3 times per second (1000ms / 6 = 167ms)
      
      if (currentTime - detailsBlinkTime >= FAST_BLINK_INTERVAL) {
        detailsBlinkTime = currentTime;
        detailsBlinkState = !detailsBlinkState;
      }
      
      // Blink port scan LED if scanning
      if (details_port_scan_led) {
        if (port_scan_in_progress) {
          lv_obj_set_style_bg_color(details_port_scan_led, 
            detailsBlinkState ? COLOR_INDICATOR_ON : COLOR_INDICATOR_OFF, 0);
        } else {
          lv_obj_set_style_bg_color(details_port_scan_led, COLOR_INDICATOR_OFF, 0);
        }
      }
      
      // Blink ping LED if pinging
      if (details_ping_led) {
        if (ping_in_progress) {
          lv_obj_set_style_bg_color(details_ping_led, 
            detailsBlinkState ? COLOR_INDICATOR_ON : COLOR_INDICATOR_OFF, 0);
        } else {
          lv_obj_set_style_bg_color(details_ping_led, COLOR_INDICATOR_OFF, 0);
        }
      }
    }
    
    // Handle refresh of device details screen when scan/ping completes
    if (need_details_refresh && details_screen && lv_scr_act() == details_screen) {
      need_details_refresh = false;
      if (selected_device_index >= 0) {
        int idx = selected_device_index;
        destroyDeviceDetailsScreen();
        createDeviceDetailsScreen(idx);
        Serial.println("[LVGL] Refreshed device details screen");
      }
    }
    
    lv_timer_handler();
    xSemaphoreGive(lvgl_mutex);
    } else {
      Serial.println("[LVGL] Failed to acquire mutex - skipping frame");
    }
    vTaskDelay(xDelay);
  }
}

// Probe a chunk of IPs to populate ARP cache using direct ARP requests
void probeIPChunk(IPAddress networkBase, IPAddress localIP, int start, int end) {
  if (!activeProbeEnabled) {
    return;
  }
  
  // Get the network interface
  struct netif *netif = netif_default;
  if (netif == NULL) {
    Serial.println("[PROBE] ERROR: No network interface available");
    return;
  }
  
  for (int i = start; i < end; i++) {
    IPAddress target = IPAddress(networkBase[0], networkBase[1], networkBase[2], i);
    
    // Skip our own IP
    if (target == localIP) continue;
    
    // Send ARP request using lwIP's etharp_request function
    // This is the PROPER way to populate ARP cache on ESP32
    ip4_addr_t ipaddr;
    IP4_ADDR(&ipaddr, target[0], target[1], target[2], target[3]);
    
    // etharp_request sends an ARP "who-has" packet for the target IP
    // If the device exists, it will respond and populate the ARP table
    etharp_request(netif, &ipaddr);
    
    vTaskDelay(pdMS_TO_TICKS(5));  // Small delay between ARP requests
  }
}

// Perform network scan - scan local network for clients via ARP
void performNetworkScan()
{
  if (!wifiConnected || WiFi.getMode() != WIFI_STA) {
    Serial.println("[SCAN] Not connected to WiFi network");
    scanInProgress = false;
    return;
  }
  
  scanInProgress = true;
  Serial.println("[SCAN] Starting network scan...");
  Serial.printf("[SCAN] Our IP: %s\n", WiFi.localIP().toString().c_str());
  Serial.printf("[SCAN] Gateway: %s\n", WiFi.gatewayIP().toString().c_str());
  Serial.printf("[SCAN] Subnet: %s\n", WiFi.subnetMask().toString().c_str());
  
  // Track which devices we've already queued during THIS scan to avoid duplicates
  std::vector<String> queuedThisScan;
  
  // Get our IP and subnet to scan (before acquiring mutex)
  IPAddress localIP = WiFi.localIP();
  IPAddress subnet = WiFi.subnetMask();
  
  // Calculate network base (assumes /24 network)
  IPAddress networkBase = IPAddress(
    localIP[0] & subnet[0],
    localIP[1] & subnet[1],
    localIP[2] & subnet[2],
    localIP[3] & subnet[3]
  );
  
  Serial.printf("[SCAN] Network: %d.%d.%d.x/24\n", 
                networkBase[0], networkBase[1], networkBase[2]);
  Serial.printf("[SCAN] ARP_TABLE_SIZE = %d (using chunked scan)\n", ARP_TABLE_SIZE);
  
  // Strategy: Scan in chunks to avoid overflowing the 30-entry ARP table
  IPAddress gateway = WiFi.gatewayIP();  // Keep gateway for timestamp refresh later
  
  for (int chunk = 0; chunk < 9; chunk++) {  // 9 chunks of 30 IPs each = 270 total
    int start = 1 + (chunk * 30);  // Start from .1, not .0
    int end = start + 30;
    if (end > 254) end = 254;
    
    Serial.printf("[SCAN] Scanning IPs %d-%d...\n", start, end);
    
    // Send ARP requests for THIS chunk and wait for responses (NO mutex needed for probing)
    if (activeProbeEnabled) {
      Serial.printf("[PROBE] Sending ARP requests: IPs %d-%d...\n", start, end);
      probeIPChunk(networkBase, localIP, start, end);
      vTaskDelay(pdMS_TO_TICKS(300));  // Wait for ARP responses to arrive and populate cache
    }
    
    // Read ARP table for this chunk (acquire/release mutex for EACH entry)
    Serial.printf("[SCAN] Reading ARP table for chunk %d...\n", chunk);
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
      ip4_addr_t *ipaddr;
      struct netif *ret_netif;
      struct eth_addr *eth_ret;
      
      if (etharp_get_entry(i, &ipaddr, &ret_netif, &eth_ret) == 1) {
        NetworkDevice dev;
        dev.ip = ip4addr_ntoa(ipaddr);
        
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
                 eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
        dev.mac = String(mac_str);
        
        // Skip our own IP
        if (dev.ip == WiFi.localIP().toString()) continue;
        
        // Leave hostname blank during scan to keep it fast
        // Hostnames will be resolved by background task
        dev.name = "";
        dev.hostnameResolved = false;  // Mark for hostname resolution
        dev.fromDHCP = false;          // Not from DHCP (will be set true if DHCP captures it later)
        
        // Initialize vendor with fast hardcoded lookup (SD lookup happens later in background)
        dev.vendor = "";
        dev.vendorResolved = false;
        dev.vendorFromSD = false;
        dev.vendorSDAttempted = false;
        
        dev.rssi = 0;
        dev.lastSeen = millis();
        
        // Do vendor lookup BEFORE acquiring mutex (fast but avoid blocking)
        String initialVendor = getMacVendorHardcoded(dev.mac);
        if (initialVendor.length() > 0) {
          Serial.printf("[SCAN] Hardcoded vendor for %s: %s\n", dev.mac.c_str(), initialVendor.c_str());
        } else {
          Serial.printf("[SCAN] No hardcoded vendor for %s - will lookup from SD\n", dev.mac.c_str());
        }
        
        // Acquire mutex just for this device update
        if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
          Serial.printf("[SCAN] Failed to acquire mutex for %s, skipping\n", dev.ip.c_str());
          continue;
        }
        
        // Check if device already exists (match by MAC only, as IP can change)
        bool found = false;
        for (auto& existing : networkDevices) {
          if (existing.mac == dev.mac) {
            // Update lastSeen - device responded to ARP probe
            existing.lastSeen = millis();
            
            // If IP changed, reset hostname resolution and queue new request
            if (existing.ip != dev.ip) {
              existing.ip = dev.ip;
              
              // Only clear hostname if NOT from DHCP (DHCP is authoritative)
              if (!existing.fromDHCP) {
                existing.hostnameResolved = false;
                existing.name = "";  // Clear old name
              }
              
              // Queue new hostname resolution request
              HostnameRequest req;
              strncpy(req.ip, dev.ip.c_str(), sizeof(req.ip) - 1);
              req.ip[sizeof(req.ip) - 1] = '\0';  // Ensure null termination
              strncpy(req.mac, dev.mac.c_str(), sizeof(req.mac) - 1);
              req.mac[sizeof(req.mac) - 1] = '\0';  // Ensure null termination
              if (xQueueSend(hostname_queue, &req, 0) != pdTRUE) {
                Serial.printf("[SCAN] WARNING: Hostname queue full, couldn't queue %s\n", dev.ip.c_str());
              }
            } else if (!existing.hostnameResolved) {
              // IP same, but hostname not yet resolved - re-queue for another attempt
              // But ONLY if we haven't already queued it during this scan
              bool alreadyQueued = false;
              for (const auto& mac : queuedThisScan) {
                if (mac == dev.mac) {
                  alreadyQueued = true;
                  break;
                }
              }
              
              if (!alreadyQueued) {
                HostnameRequest req;
                strncpy(req.ip, dev.ip.c_str(), sizeof(req.ip) - 1);
                req.ip[sizeof(req.ip) - 1] = '\0';  // Ensure null termination
                strncpy(req.mac, dev.mac.c_str(), sizeof(req.mac) - 1);
                req.mac[sizeof(req.mac) - 1] = '\0';  // Ensure null termination
                if (xQueueSend(hostname_queue, &req, 0) == pdTRUE) {
                  Serial.printf("[SCAN] Re-queued hostname lookup for %s (no hostname yet)\n", dev.ip.c_str());
                  queuedThisScan.push_back(dev.mac);  // Remember we queued this one
                }
              }
            }
            found = true;
            break;
          }
        }
        
        if (!found) {
          // NEW device - use pre-computed vendor (already looked up before mutex)
          dev.vendor = initialVendor;
          dev.vendorResolved = true;     // Hardcoded lookup complete
          dev.vendorFromSD = false;      // Not from SD (green)
          dev.vendorSDAttempted = false; // Haven't tried SD yet
          
          networkDevices.push_back(dev);
          Serial.printf("[SCAN] Found NEW device: %s - %s\n", dev.ip.c_str(), dev.mac.c_str());
          
          // Queue hostname resolution request
          HostnameRequest req;
          strncpy(req.ip, dev.ip.c_str(), sizeof(req.ip) - 1);
          req.ip[sizeof(req.ip) - 1] = '\0';  // Ensure null termination
          strncpy(req.mac, dev.mac.c_str(), sizeof(req.mac) - 1);
          req.mac[sizeof(req.mac) - 1] = '\0';  // Ensure null termination
          if (xQueueSend(hostname_queue, &req, 0) != pdTRUE) {
            Serial.printf("[SCAN] WARNING: Hostname queue full, couldn't queue %s\n", dev.ip.c_str());
          } else {
            Serial.printf("[SCAN] Queued hostname lookup for %s\n", dev.ip.c_str());
            queuedThisScan.push_back(dev.mac);  // Remember we queued this one
          }
        }
        
        // Release mutex immediately after updating this device
        xSemaphoreGive(devices_mutex);
      }
    }
    
    // Small delay between chunks to allow other tasks to run
    vTaskDelay(pdMS_TO_TICKS(10));
    
  }  // End chunk loop
  
  Serial.println("[SCAN] =====================================");
  
  // Upgrade vendors to orange (SD database) after scan completes
  // Do this BEFORE cleanup so we can upgrade devices while SD mutex is free
  // Binary search is instant, so no need to limit upgrades anymore
  int upgradeCount = 0;
  
  // Collect devices needing upgrade first (outside SD mutex)
  std::vector<String> devicesToUpgrade;
  if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
    for (auto& device : networkDevices) {
      // Upgrade ANY device that hasn't been upgraded yet (ignore hostname status)
      // Yellow will overwrite orange in display anyway, so upgrade everything
      if (!device.vendorFromSD && !device.vendorSDAttempted) {
        devicesToUpgrade.push_back(device.mac);
      }
    }
    xSemaphoreGive(devices_mutex);
  }
  
  // Now upgrade each device (with mutex released for SD operations)
  for (const String& deviceMac : devicesToUpgrade) {
    String deviceOui = deviceMac.substring(0, 8);
    deviceOui.toUpperCase();
    deviceOui.replace(":", "");
    deviceOui.replace("-", "");
    
    if (deviceOui.length() == 6) {
      // Do SD lookup (no mutex needed)
      String macForLookup = deviceOui.substring(0, 2) + ":" + deviceOui.substring(2, 4) + ":" + deviceOui.substring(4, 6) + ":00:00:00";
      Serial.printf("[SCAN] Upgrading vendor for %s...\n", deviceMac.c_str());
      String vendor = getMacVendorFromSD(macForLookup);
      
      // Update device with result
      if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (auto& dev : networkDevices) {
          if (dev.mac == deviceMac) {
            if (vendor.length() > 0) {
              dev.vendor = vendor;
              dev.vendorFromSD = true;
              dev.vendorSDAttempted = true;  // Mark attempted only on success
              Serial.printf("[SCAN] Upgraded %s: %s\n", deviceMac.c_str(), vendor.c_str());
              upgradeCount++;
            } else {
              // Mark attempted so we don't retry every scan (likely locally-administered MAC)
              dev.vendorSDAttempted = true;
              Serial.printf("[SCAN] No SD vendor for %s (locally-administered or not in IEEE DB)\n", deviceMac.c_str());
            }
            break;
          }
        }
        xSemaphoreGive(devices_mutex);
      }
    }
  }
  
  // Acquire mutex for final cleanup operations
  if (xSemaphoreTake(devices_mutex, pdMS_TO_TICKS(500)) != pdTRUE) {
    Serial.println("[SCAN] Failed to acquire devices mutex for cleanup");
    scanInProgress = false;
    return;
  }
  
  // Always update gateway timestamp (it's always reachable via our connection)
  for (auto& existing : networkDevices) {
    if (existing.ip == gateway.toString()) {
      existing.lastSeen = millis();
      Serial.printf("[SCAN] Refreshed gateway timestamp: %s\n", gateway.toString().c_str());
      break;
    }
  }
  
  // Remove devices based on configured timeout (if not set to "never")
  unsigned long currentTime = millis();
  
  if (deviceTimeoutSeconds > 0) {
    unsigned long timeoutMs = deviceTimeoutSeconds * 1000;
    for (int i = networkDevices.size() - 1; i >= 0; i--) {
      if (currentTime - networkDevices[i].lastSeen > timeoutMs) {
        Serial.printf("[SCAN] Removing stale device (not seen for %ds): %s - %s\n", 
                      deviceTimeoutSeconds, networkDevices[i].ip.c_str(), networkDevices[i].mac.c_str());
        networkDevices.erase(networkDevices.begin() + i);
      }
    }
  }
  // else: deviceTimeoutSeconds == 0, keep devices forever
  
  initialScanDone = true;
  deviceListChanged = true;
  scanInProgress = false;
  Serial.printf("[SCAN] Complete! Total devices in list: %d\n", networkDevices.size());
  xSemaphoreGive(devices_mutex);  // Release devices mutex
  
  if (networkDevices.size() == 0) {
    Serial.println("[SCAN] No devices found. This is unusual after a ping sweep.");
  }
}

// Network monitoring task
void NetworkTask(void *parameter)
{
  const TickType_t xDelay = pdMS_TO_TICKS(2000);  // Update every 2 seconds
  
  while (1)
  {
    // Handle WiFi setup scan requests via queue (non-blocking check)
    uint8_t msg;
    if (xQueueReceive(wifi_scan_queue, &msg, 0) == pdTRUE && !wifi_scanning) {
      // Take scan mutex to prevent client scanning during WiFi scan
      if (xSemaphoreTake(scan_mutex, 0) == pdTRUE) {
        wifi_scanning = true;
        
        Serial.println("[WiFi Setup] Scan request received, starting scan...");
      
      // Switch to STA mode temporarily to scan
      WiFi.mode(WIFI_STA);
      vTaskDelay(pdMS_TO_TICKS(500));
      
      // Scan for networks
      int n = WiFi.scanNetworks();
      Serial.printf("[WiFi Setup] Found %d networks\n", n);
      
      // Update WiFi networks list with new scan results
      unsigned long currentTime = millis();
      for (int i = 0; i < n; i++) {
        String ssid = WiFi.SSID(i);
        int rssi = WiFi.RSSI(i);
        int channel = WiFi.channel(i);
        wifi_auth_mode_t encType = WiFi.encryptionType(i);
        bool isOpen = (encType == WIFI_AUTH_OPEN);
        
        // Check if network already exists
        bool found = false;
        for (auto& net : wifiNetworks) {
          if (net.ssid == ssid) {
            net.rssi = rssi;  // Update signal strength
            net.channel = channel;
            net.isOpen = isOpen;
            net.encryptionType = encType;
            net.lastSeen = currentTime;
            found = true;
            break;
          }
        }
        
        // Add new network if not found
        if (!found) {
          WiFiNetwork newNet;
          newNet.ssid = ssid;
          newNet.rssi = rssi;
          newNet.channel = channel;
          newNet.isOpen = isOpen;
          newNet.encryptionType = encType;
          newNet.lastSeen = currentTime;
          wifiNetworks.push_back(newNet);
          Serial.printf("[WiFi Setup] New network: %s (%d dBm, Ch %d)\n", ssid.c_str(), rssi, channel);
        }
      }
      WiFi.scanDelete();
      
      // Remove networks not seen for 5 minutes
      for (int i = wifiNetworks.size() - 1; i >= 0; i--) {
        if (currentTime - wifiNetworks[i].lastSeen > NETWORK_TIMEOUT_MS) {
          Serial.printf("[WiFi Setup] Removing stale network: %s\n", wifiNetworks[i].ssid.c_str());
          wifiNetworks.erase(wifiNetworks.begin() + i);
        }
      }
      
      Serial.printf("[WiFi Setup] Total networks in list: %d\n", wifiNetworks.size());
      
      // Update UI with results
      bool ui_updated = false;
      for (int attempt = 0; attempt < 50 && !ui_updated; attempt++) {
        if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
          Serial.printf("[WiFi Setup] Updating UI (attempt %d)...\n", attempt + 1);
          lv_obj_clean(network_list);
          
          if (wifiNetworks.size() == 0) {
            lv_obj_t *no_networks = lv_label_create(network_list);
            lv_label_set_text(no_networks, "No networks found");
            lv_obj_set_style_text_color(no_networks, lv_color_hex(0xFF0000), 0);
            lv_obj_set_style_text_font(no_networks, &lv_font_montserrat_14, 0);
          } else {
            for (size_t i = 0; i < wifiNetworks.size(); i++) {
              lv_obj_t *btn = lv_btn_create(network_list);
              lv_obj_set_style_shadow_width(btn, 0, 0);  // No shadow
              lv_obj_set_style_border_width(btn, 0, 0);  // No border
              lv_obj_set_size(btn, 440, 40);
              
              // Color-code button background by WiFi channel
              // Red for low channels (1-4), blue for high channels (11-14), gradient in between
              uint32_t channelColor = getChannelColor(wifiNetworks[i].channel);
              lv_obj_set_style_bg_color(btn, lv_color_hex(channelColor), 0);
              
              lv_obj_set_style_radius(btn, 5, 0);
              lv_obj_add_event_cb(btn, network_item_event_handler, LV_EVENT_CLICKED, NULL);
              
              lv_obj_t *label = lv_label_create(btn);
              String secType = getSecurityType(wifiNetworks[i].encryptionType);
              String labelText = wifiNetworks[i].ssid + " (" + String(wifiNetworks[i].rssi) + " dBm) Ch" + String(wifiNetworks[i].channel) + " [" + secType + "]";
              lv_label_set_text(label, labelText.c_str());
              lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
              lv_obj_align(label, LV_ALIGN_LEFT_MID, 10, 0);
              
              // Release mutex briefly every few items to allow LVGL task to process input
              if ((i % 2) == 1) {
                xSemaphoreGive(lvgl_mutex);
                vTaskDelay(pdMS_TO_TICKS(5));  // Let other tasks run
                if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
                  Serial.println("[WiFi Setup] Failed to re-acquire mutex during update");
                  ui_updated = false;
                  break; // Stop updating, we lost the lock
                }
              }
            }
          }
          
          // Only update layout and give mutex if we still hold it (which we do if we didn't break, OR if we broke but re-acquired? No.)
          // Wait, if we broke because we FAILED to acquire, we don't hold it.
          // If we broke for other reasons (none here), we hold it.
          // So if we failed to acquire, we must NOT give it.
          
          // Actually, let's just use a goto or a flag.
          if (xSemaphoreGetMutexHolder(lvgl_mutex) == xTaskGetCurrentTaskHandle()) {
             lv_obj_update_layout(network_list);
             xSemaphoreGive(lvgl_mutex);
             ui_updated = true;
          } else {
             // We lost the mutex, so update failed
             ui_updated = false;
          }
          Serial.println("[WiFi Setup] UI updated successfully!");
        } else {
          vTaskDelay(pdMS_TO_TICKS(20));
        }
      }
      
      if (!ui_updated) {
        Serial.println("[WiFi Setup] ERROR: Failed to update UI!");
      }
      
      // Restore previous WiFi mode
      String ssid = getConfigValue(0);
      if (ssid.length() > 0 && wifiConnected) {
        // Was connected in STA mode, restore it
        WiFi.mode(WIFI_STA);
        Serial.println("[WiFi Setup] Restored STA mode");
      } else {
        // Restore AP mode
        String apSSID = getConfigValue(2);
        String apPassword = getConfigValue(3);
        if (apSSID == "" || apPassword == "") {
          apSSID = "Network Analyser";
          apPassword = "Epoxy123";
        }
        WiFi.mode(WIFI_AP);
        WiFi.softAP(apSSID.c_str(), apPassword.c_str());
        Serial.println("[WiFi Setup] Restored AP mode");
      }
      
      vTaskDelay(pdMS_TO_TICKS(200));
      wifi_scanning = false;
      xSemaphoreGive(scan_mutex);  // Release scan mutex
      Serial.println("[WiFi Setup] Scan complete, mode restored");
      } else {
        Serial.println("[WiFi Setup] Scan already in progress, skipping");
      }
    }
    
    // Update display - but only if we're on the network stats screen
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
      lv_obj_t *active_screen = lv_scr_act();
      bool should_update = (active_screen == main_screen);
      xSemaphoreGive(lvgl_mutex);
      
      if (should_update) {
        updateNetworkStats();
      }
    }
    
    // Handle OTA
    if (WiFi.getMode() == WIFI_STA)
    {
      ArduinoOTA.handle();
    }
    
    vTaskDelay(xDelay);
  }
}

// Periodic WiFi network scanning task
void WiFiScanTask(void *parameter)
{
  while (1)
  {
    // Sleep for the scan interval
    vTaskDelay(pdMS_TO_TICKS(WIFI_SCAN_INTERVAL_MS));
    
    // Check if we're currently viewing the WiFi Networks screen (thread-safe)
    // Don't scan if on password screen to improve keyboard responsiveness
    bool should_scan = false;
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
      lv_obj_t *active_screen = lv_scr_act();
      // Only scan if on wifi_setup_screen AND NOT on password_screen
      should_scan = (active_screen == wifi_setup_screen && !wifi_scanning);
      // Extra check: if password_screen is visible, don't scan
      if (should_scan && password_screen != nullptr) {
        should_scan = (active_screen != password_screen);
      }
      xSemaphoreGive(lvgl_mutex);
    }
    
    if (should_scan) {
      Serial.println("[WiFiScanTask] Triggering periodic WiFi scan...");
      uint8_t msg = 1;
      xQueueSend(wifi_scan_queue, &msg, 0);
    }
  }
}

// Periodic client scanning task
void ClientScanTask(void *parameter)
{
  // Perform first scan immediately after WiFi connects
  while (!wifiConnected) {
    vTaskDelay(pdMS_TO_TICKS(100));  // Wait for WiFi to connect
  }
  
  while (1)
  {
    // Check internet connectivity when connected in STA mode
    if (wifiConnected) {
      wifi_mode_t mode = WiFi.getMode();
      if (mode == WIFI_STA || mode == WIFI_AP_STA) {
        internetConnected = (WiFi.status() == WL_CONNECTED);
        
        // Query public IP every 5 minutes when internet is connected
        static unsigned long lastPublicIPCheck = 0;
        if (internetConnected && (millis() - lastPublicIPCheck > 300000 || publicIP == "---")) {
          lastPublicIPCheck = millis();
          publicIP = getPublicIP();
        }
      }
    } else {
      internetConnected = false;
      publicIP = "---";
    }
    
    // Only scan when connected in STA mode and not doing WiFi network scan
    if (wifiConnected && !wifi_scanning) {
      wifi_mode_t mode = WiFi.getMode();
      if (mode == WIFI_STA || mode == WIFI_AP_STA) {
        // Take scan mutex to prevent WiFi scanning during client scan
        if (xSemaphoreTake(scan_mutex, 0) == pdTRUE) {
          Serial.println("[ClientScanTask] Starting periodic client scan...");
          performNetworkScan();
          xSemaphoreGive(scan_mutex);  // Release scan mutex
        } else {
          Serial.println("[ClientScanTask] Scan already in progress, skipping");
        }
      }
    }
    
    // Sleep for the configured probe interval AFTER the scan (convert seconds to milliseconds)
    unsigned long scanInterval = probeIntervalSeconds * 1000;
    if (scanInterval < 3000) scanInterval = 3000;  // Minimum 3 seconds
    vTaskDelay(pdMS_TO_TICKS(scanInterval));
  }
}

void setup()
{
  Serial.begin(115200);
  delay(2000);  // Extra delay to ensure serial monitor connects
  Serial.println("[INIT] Network Analyzer Starting...");
  
  // ============================================================================
  // CRITICAL INITIALIZATION ORDER: Display MUST be initialized BEFORE SD card
  // ============================================================================
  // The display controller (ST7701) uses Software SPI for initialization via
  // the Arduino_SWSPI bus (pins: TFT_SCK=48, TFT_MOSI=47, TFT_CS=39).
  // The SD card uses hardware SPI on the SAME pins (SCK=48, MOSI=47, CS=42).
  //
  // PROBLEM: If SD card initializes first and configures hardware SPI, then
  // tft->begin() reconfigures GPIO pins 47/48 for Software SPI, which disrupts
  // the SD card's SPI bus configuration. This causes "Card Failed" errors after
  // ~7 seconds when SD card operations resume.
  //
  // SOLUTION: Initialize display FIRST so Software SPI completes and releases
  // the pins, THEN initialize hardware SPI fresh for SD card. This prevents any
  // GPIO reconfiguration conflicts.
  //
  // This order matches the proven-stable NMEATouch20 implementation.
  // ============================================================================
  
  Serial.println("[INIT] Initializing display...");
  
  // Configure CS pins HIGH before any SPI operations
  pinMode(TFT_CS, OUTPUT);
  digitalWrite(TFT_CS, HIGH);
  pinMode(42, OUTPUT);  // SD_CS_PIN
  digitalWrite(42, HIGH);
  
  // Initialize touch panel
  touch_panel.begin();
  touch_panel.setRotation(TAMC_GT911_ROTATION);
  touch_panel.setResolution(TFT_WIDTH, TFT_HEIGHT);
  
  // Initialize display - backlight stays OFF during init
  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, LOW);
  
  tft->begin();
  tft->fillScreen(BLACK);
  Serial.println("[INIT] Display initialized");
  
  // Initialize LittleFS
  if (!LittleFS.begin())
  {
    Serial.println("[ERROR] LittleFS mount failed! Attempting to format...");
    if (!LittleFS.begin(true)) {  // true = format if mount fails
      Serial.println("[ERROR] LittleFS format failed!");
      return;
    }
    Serial.println("[INIT] LittleFS formatted successfully");
  }
  Serial.println("[INIT] LittleFS mounted");
  
  // Create SD mutex BEFORE any SD operations
  sdFileMutex = xSemaphoreCreateMutex();
  if (!sdFileMutex) {
    Serial.println("[ERROR] Failed to create SD mutex!");
    return;
  }
  
  // **NOW initialize SD card - AFTER display is done with Software SPI**
  Serial.println("[INIT] Starting SD card initialization...");
  
  // SD card pin assignments
  const int SD_CS_PIN = 42;    // SD card CS (unique)
  const int SHARED_SCK = 48;   // Same as display SCK
  const int SHARED_MISO = 41;  // SD card MISO
  const int SHARED_MOSI = 47;  // Same as display MOSI
  
  Serial.printf("[INIT] SD pins - CS:%d SCK:%d MOSI:%d MISO:%d\n",
                SD_CS_PIN, SHARED_SCK, SHARED_MOSI, SHARED_MISO);
  
  // Configure the hardware SPI bus for SD card
  SPI.begin(SHARED_SCK, SHARED_MISO, SHARED_MOSI, -1);
  
  // Try progressively slower speeds until one works (matching NMEATouch20)
  bool success = false;
  
  Serial.println("[INIT] Trying 50MHz...");
  success = SD.begin(SD_CS_PIN, SPI, 50000000);
  
  if (!success) {
    Serial.println("[INIT] Trying 40MHz...");
    success = SD.begin(SD_CS_PIN, SPI, 40000000);
  }
  
  if (!success) {
    Serial.println("[INIT] Trying 30MHz...");
    success = SD.begin(SD_CS_PIN, SPI, 30000000);
  }
  
  if (!success) {
    Serial.println("[INIT] Trying 25MHz...");
    success = SD.begin(SD_CS_PIN, SPI, 25000000);
  }
  
  if (!success) {
    Serial.println("[INIT] Trying 10MHz...");
    success = SD.begin(SD_CS_PIN, SPI, 10000000);
  }
  
  if (!success) {
    Serial.println("[INIT] Trying 4MHz...");
    success = SD.begin(SD_CS_PIN, SPI, 4000000);
  }
  
  if (!success) {
    Serial.println("[INIT] Trying 1MHz...");
    success = SD.begin(SD_CS_PIN, SPI, 1000000);
  }
  
  if (success) {
    uint8_t cardType = SD.cardType();
    
    // Check if card is actually present and usable
    if (cardType != CARD_NONE && SD.totalBytes() > 0) {
      sdCardReady = true;
      Serial.println("[INIT] ✓ SD card mounted successfully");
      
      // Print SD card info
      Serial.print("[INIT] SD Card Type: ");
      if (cardType == CARD_MMC) Serial.println("MMC");
      else if (cardType == CARD_SD) Serial.println("SD");
      else if (cardType == CARD_SDHC) Serial.println("SDHC");
      else Serial.println("UNKNOWN");
      
      uint64_t cardSize = SD.cardSize() / (1024 * 1024);
      Serial.printf("[INIT] SD Card Size: %lluMB\n", cardSize);
      Serial.printf("[INIT] Total space: %lluMB\n", SD.totalBytes() / (1024 * 1024));
      Serial.printf("[INIT] Used space: %lluMB\n", SD.usedBytes() / (1024 * 1024));
      
      // Check OUI database status
      if (SD.exists(OUI_DATABASE_FILE)) {
        File file = SD.open(OUI_DATABASE_FILE, FILE_READ);
        if (file) {
          Serial.printf("[INIT] OUI database found: %d bytes\n", file.size());
          file.close();
        }
      } else {
        Serial.println("[INIT] OUI database not found - will download after WiFi connects");
      }
    } else {
      Serial.println("[INIT] ✗ SD card detected but not usable (no media or invalid)");
    }
  } else {
    Serial.println("[INIT] ✗ SD card mount failed - using offline vendor database only");
    Serial.println("[INIT] Check: 1) SD card inserted? 2) Card formatted as FAT32? 3) Card not corrupted?");
  }
  
  // Create remaining mutexes and queues
  lvgl_mutex = xSemaphoreCreateMutex();
  fs_mutex = xSemaphoreCreateMutex();
  scan_mutex = xSemaphoreCreateMutex();
  devices_mutex = xSemaphoreCreateMutex();
  wifi_scan_queue = xQueueCreate(5, sizeof(uint8_t));
  hostname_queue = xQueueCreate(100, sizeof(HostnameRequest));
  
  if (fs_mutex == NULL || lvgl_mutex == NULL || scan_mutex == NULL || devices_mutex == NULL || sdFileMutex == NULL || wifi_scan_queue == NULL || hostname_queue == NULL)
  {
    Serial.println("[ERROR] Failed to create mutexes or queues!");
    return;
  }
  
  // Read configuration
  readConfigFile();
  
  // Initialize LVGL
  lv_init();
  display_object = lv_display_create(TFT_WIDTH, TFT_HEIGHT);
  lv_display_set_color_format(display_object, LV_COLOR_FORMAT_RGB565);
  lv_display_set_flush_cb(display_object, my_disp_flush);
  init_display_buffers(display_object);
  
  // Register touch input
  lv_indev_t *indev = lv_indev_create();
  lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
  lv_indev_set_read_cb(indev, my_touch_read_cb);
  lv_indev_set_display(indev, display_object);
  
  // Create LVGL task ONLY - needed for splash screen during WiFi/OUI operations
  // Other tasks created AFTER WiFi and OUI update to avoid interference
  // Priority 1 (lower than network to prevent packet loss)
  xTaskCreatePinnedToCore(LVGLTask, "LVGL", 8192, NULL, 1, NULL, 1);
  delay(100); // Let LVGL task start
  
  // Initialize WiFi BEFORE creating network tasks
  // This also handles OUI database check/download before heavy tasks start
  initWiFi();
  
  // NOW create network scanning tasks AFTER WiFi and OUI operations complete
  // Priorities: Network operations (High=2), Display/Scan (Medium=1), Background (Low=0)
  xTaskCreatePinnedToCore(NetworkTask, "Network", 4096, NULL, 2, NULL, 0);
  xTaskCreatePinnedToCore(DHCPSnoopTask, "DHCPSnoop", 3072, NULL, 2, NULL, 0);  // Network timing critical
  xTaskCreatePinnedToCore(WiFiScanTask, "WiFiScan", 2048, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(ClientScanTask, "ClientScan", 4096, NULL, 1, NULL, 0);
  
  // Vendor upgrades now integrated into ClientScanTask (no separate task needed)
  
  // Create hostname resolver tasks for parallel resolution
  // Limited to 2 tasks to avoid exhausting UDP buffer pool (each opens 4+ sockets)
  for (int i = 0; i < 2; i++) {  // Reduced from 8 to prevent ENOMEM errors
    char taskName[32];
    snprintf(taskName, sizeof(taskName), "HostnameResolver-%d", i);
    xTaskCreatePinnedToCore(HostnameResolverTask, taskName, 4096, (void*)i, 0, NULL, 0); // Priority 0 (Lowest)
  }
  
  // Start SD card check task if card was initially detected
  if (sdCardReady) {
    xTaskCreatePinnedToCore(sdCardCheckTask, "SD Card Check", 2048, NULL, 1, NULL, 1);
    Serial.println("[INIT] SD card check task started");
  }
  
  // Always create both screens for swipe navigation
  createWiFiSetupUI();
  createNetworkStatsUI();
  create_settings_screen();
  
  // Load appropriate starting screen based on WiFi mode
  if (WiFi.getMode() == WIFI_AP) {
    // AP mode - start on WiFi setup screen and trigger scan
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
      lv_scr_load(wifi_setup_screen);
      xSemaphoreGive(lvgl_mutex);
    }
    
    Serial.println("[WiFi Setup] Triggering automatic initial scan...");
    delay(100);
    uint8_t msg = 1;
    xQueueSend(wifi_scan_queue, &msg, 0);
  } else {
    // STA mode - start on network analyzer screen
    if (xSemaphoreTake(lvgl_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
      lv_scr_load(main_screen);
      xSemaphoreGive(lvgl_mutex);
    }
  }
  
  // Settings can be changed via touchscreen settings page
  Serial.println("[INIT] Display ready");
  
  Serial.println("[INIT] Setup complete!");
}

void loop()
{
  vTaskDelay(1000);
}

