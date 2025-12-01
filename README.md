# Network Analyzer

A comprehensive WiFi network monitoring and analysis tool for ESP32-S3 with touchscreen display.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)
![Platform](https://img.shields.io/badge/platform-ESP32--S3-orange.svg)

## Overview

Network Analyzer is a feature-rich network monitoring tool designed for the Guition ESP32-4848S040 development board. It provides real-time network analysis with an intuitive touchscreen interface, making it perfect for network diagnostics, device discovery, and security monitoring.

## Features

### Core Functionality
- **Real-time Network Scanning** - Discover all devices on your network via ARP scanning
- **Device Identification** - 3-tier identification system:
  - 🟡 Yellow: DHCP snooping (authoritative hostname)
  - 🟢 Green: Hardcoded vendor database (fast lookup)
  - 🟠 Orange: IEEE OUI database (40,000+ vendors from SD card)
- **WiFi Management** - Dual mode operation (AP/STA) with persistent credentials
- **Port Scanning** - Identify open ports and services on network devices
- **Ping Testing** - Network connectivity and latency testing
- **Connection Monitoring** - Track device connections/disconnections

### Advanced Features
- **DHCP Snooping** - Passive hostname extraction from DHCP traffic
- **MAC Vendor Lookup** - Automatic manufacturer identification
- **OUI Database** - 6MB IEEE database with binary search indexing
- **Signal Strength** - Real-time RSSI monitoring
- **Internet Connectivity** - Auto-detection of internet access
- **NTP Time Sync** - Network time synchronization with timezone support

### User Interface
- **480×480 Touchscreen** - LVGL-based responsive UI
- **Multiple Screens**:
  - WiFi Networks - Available network scanner
  - Network Clients - Connected device list
  - Device Details - In-depth device information
  - Settings - Configuration and preferences
- **Visual Indicators** - LED status indicators for scanning operations

## Hardware Requirements

### Required Components
- **Guition ESP32-4848S040** development board
  - ESP32-S3 dual-core processor
  - 480×480 LCD display (ST7701 controller)
  - GT911 capacitive touch panel
  - 8MB PSRAM
  - 16MB Flash

### Optional Components
- **MicroSD Card** (recommended)
  - For IEEE OUI database storage (~6MB)
  - Vendor identification for 40,000+ manufacturers
  - FAT32 formatted

## Software Requirements

### Development Environment
- **PlatformIO** (or Arduino IDE)
- **ESP32 Arduino Core** (v2.0.0 or higher)

### Dependencies
- **LVGL** (v9.2.2) - Graphics library
- **Arduino_GFX** - Display driver
- **TAMC_GT911** - Touch controller
- **LittleFS** - Configuration storage
- **SD** - MicroSD card access

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/carlosfandang0/NetworkAnalyser.git
cd NetworkAnalyser
```

### 2. Open in PlatformIO
```bash
pio run
```

### 3. Configure WiFi (First Time)
Edit `data/config.txt`:
```
0:T WiFi SSID=YourNetworkName
1:T WiFi Password=YourPassword
2:T AP SSID=Network Analyser
3:T AP Password=Epoxy123
4:B Active Probe=1
5:I Probe Interval=30
6:I Device Timeout=0
7:I Timezone Offset=0
```

### 4. Upload Filesystem
```bash
pio run --target uploadfs
```

### 5. Upload Firmware
```bash
pio run --target upload
```

## Configuration

### Settings Menu
Access via gear icon (⚙️) on any screen:

- **Active Probe** - Enable/disable active network probing
- **Probe Interval** - Scan frequency (5-60 seconds)
- **Device Timeout** - Remove inactive devices (0=never)
- **Timezone** - UTC offset (-12 to +12 hours)
- **WiFi Network** - Change connected network
- **Factory Reset** - Restore default settings

### OUI Database Update
The device automatically checks for OUI database updates every 30 days. Manual update available in Settings menu.

## Usage

### Initial Setup
1. Power on device
2. Device creates "Network Analyser" WiFi access point
3. Connect to AP and configure your network via touchscreen
4. Device connects to your network and starts scanning

### Navigation
- **Networks Button** - View available WiFi networks
- **Clients Button** - See connected devices
- **Settings Button** - Configure preferences
- **Device Tap** - View detailed device information

### Device Details
Tap any device to see:
- Hostname and IP address
- MAC address and vendor
- Port scan results
- Ping statistics (min/max/avg latency)

## Architecture

### Memory-Efficient Design
- **Chunked Merge Sort** - Sorts 38,439 OUI entries with only 20KB RAM
- **Binary Search Index** - Fast vendor lookups (~15 comparisons)
- **FreeRTOS Tasks** - Concurrent operations without blocking UI
- **PSRAM Utilization** - Large buffers in external RAM

### Task Structure
| Task | Priority | Core | Function |
|------|----------|------|----------|
| LVGL | 1 | 1 | UI rendering and touch input |
| Network | 2 | 0 | WiFi scanning and management |
| ClientScan | 1 | 0 | Device discovery via ARP |
| DHCPSnoop | 2 | 0 | Hostname extraction |
| HostnameResolver | 0 | 0 | Background name resolution |
| PortScan | 1 | 0 | Service discovery |
| Ping | 1 | 0 | Connectivity testing |

## Troubleshooting

### WiFi Connection Issues
- **Symptom**: Device fails to connect to network
- **Solution**: Wait 1.5 seconds after boot for WiFi hardware stabilization (already implemented)
- **Alternative**: Use AP mode and manually configure

### No Yellow Devices
- **Symptom**: All devices show green/orange, none yellow
- **Cause**: No recent DHCP activity
- **Solution**: Reconnect a device to trigger DHCP request

### SD Card Not Detected
- **Check**: Card inserted and formatted as FAT32
- **Check**: Card not corrupted
- **Fallback**: Hardcoded vendor database still works (common vendors only)

## Performance

### Scan Speed
- **Network Scan**: ~3 seconds for /24 subnet (254 addresses)
- **Vendor Lookup**: <1ms (binary search)
- **DHCP Snoop**: Real-time (passive listening)
- **Port Scan**: ~2 seconds (16 common ports)

### Memory Usage
- **PSRAM**: ~150KB (LVGL buffers)
- **DRAM**: ~180KB (FreeRTOS + application)
- **Flash**: ~1.2MB (firmware)
- **LittleFS**: <10KB (configuration)
- **SD Card**: ~6MB (OUI database)

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on hardware
5. Submit a pull request

## License

This project is licensed under the **GNU General Public License v3.0**.

You are free to:
- Use commercially
- Modify and distribute
- Use privately

Under the conditions:
- Disclose source
- Same license for modifications
- State changes

See [LICENSE](LICENSE) file for full terms.

## Author

**Carl Schofield**
- GitHub: [@carlosfandang0](https://github.com/carlosfandang0)

## Version History

### v1.0.0 (November 2025)
- Initial public release
- WiFi network scanning
- Device identification (3-tier system)
- DHCP snooping
- Port scanning and ping
- OUI database integration
- Touchscreen UI with LVGL
- Settings management

## Support

For issues, questions, or suggestions:
- **GitHub Issues**: [Create an issue](https://github.com/carlosfandang0/NetworkAnalyser/issues)

---

**Note**: This is network monitoring software intended for educational and authorized network analysis only. Always obtain permission before scanning networks you do not own or administer.
