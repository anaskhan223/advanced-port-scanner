# Advanced Network Port Scanner 🚀

A powerful and comprehensive network port scanning tool written in Python.  
Designed for ethical hackers, penetration testers, and network administrators.

---

## ✨ Features

- 🔍 **TCP & UDP Port Scanning**
- ⚡ **Multithreaded scanning** (up to 500 threads)
- 🧠 **OS Detection** using TTL and open ports
- 🛰️ **Network-wide scanning** using CIDR (e.g., `192.168.1.0/24`)
- 📡 **Host Discovery** (Ping, TCP Ping, ARP)
- 📄 **Banner Grabbing** for service identification
- 🔐 **Stealth Scanning** (partially supported)
- 📊 **Classifies Open, Closed, Filtered Ports**
- 💾 **Save results** as JSON or Text
- 👨‍💻 Full **Command-line interface**

---

## 🛠️ Usage Examples

### Basic Scan
```bash
python3 port_scanner.py 192.168.1.1
