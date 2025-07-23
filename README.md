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
```

### Scan Port Range on Network
```bash
python3 port_scanner.py 192.168.1.0/24 -p 1-1000
```

### Scan All Ports
```bash
python3 port_scanner.py target.com -p all
```

### UDP Scan
```bash
python3 port_scanner.py 192.168.1.1 --udp -p 53,161,123
```

---

## 📘 Command Line Options

| Option             | Description                                             |
|--------------------|---------------------------------------------------------|
| `target`           | Target IP or network (e.g., `192.168.1.1`, `10.0.0.0/24`) |
| `-p, --ports`      | Ports to scan (e.g., `21,22,80`, `1-1000`, `common`, `all`) |
| `-t, --timeout`    | Timeout in seconds (default: 3)                         |
| `--threads`        | Maximum threads (default: 500)                          |
| `--udp`            | Perform UDP scan instead of TCP                         |
| `--show-closed`    | Show closed ports in output                             |
| `--show-filtered`  | Show filtered ports in output                           |
| `-o, --output`     | Save results to file                                    |
| `--format`         | Output format: `txt` or `json`                          |
| `-v, --verbose`    | Verbose error/debug output                              |

---

## 📦 Requirements

- Python 3.6+
- Standard libraries only (no external pip modules required)
- Root/Admin access for full functionality

---

## ⚖️ License

This project is licensed under the [MIT License](LICENSE).

---

## 📣 Author

Created by **Anas Khan (At Danger)** 🇵🇰  
Learning Ethical Hacking | Python & Networking Enthusiast  
GitHub: [your-github-profile](https://github.com/yourusername)

---

## ⚠️ Disclaimer

> This tool is intended for **educational and authorized security testing** only.  
> **Do not scan** any device, system, or network without **proper permission**.  
> Unauthorized scanning is **illegal** and unethical.
