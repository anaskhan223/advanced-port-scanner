#!/usr/bin/env python3
"""
Advanced Network Port Scanner
A comprehensive and powerful tool to scan ports on single hosts or entire networks
with advanced features including stealth scanning, OS detection, and service enumeration
"""

import socket
import threading
import ipaddress
import argparse
import sys
import time
import random
import struct
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import subprocess
import os
import json
import re

class AdvancedPortScanner:
    def __init__(self, timeout=3, max_threads=500, scan_type='tcp'):
        self.timeout = timeout
        self.max_threads = max_threads
        self.scan_type = scan_type
        self.results = {}
        self.lock = threading.Lock()
        
        # Comprehensive port ranges
        self.well_known_ports = list(range(1, 1024))
        self.registered_ports = list(range(1024, 49152))
        self.all_ports = list(range(1, 65536))
        
        # Most common ports (expanded list)
        self.common_ports = [
            # Web services
            80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090, 9443,
            # SSH and remote access
            22, 23, 3389, 5900, 5901, 5902, 5903, 5904, 5905,
            # Mail services
            25, 110, 143, 993, 995, 587, 465,
            # DNS and DHCP
            53, 67, 68,
            # File transfer
            21, 22, 69, 115, 2049,
            # Database services
            1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019,
            # Network services
            135, 139, 445, 137, 138, 161, 162, 389, 636, 88, 464,
            # VPN and tunneling
            1194, 1723, 4500, 500,
            # Monitoring and management
            161, 162, 623, 10000, 8161, 9100,
            # Gaming and streaming
            25565, 7777, 27015, 1935, 554,
            # Development and API
            3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000,
            # Container and orchestration
            2375, 2376, 2377, 6443, 8080, 10250, 10255,
            # Message queues
            5672, 15672, 9092, 2181, 4369, 25672,
            # Proxies and load balancers
            3128, 8080, 1080, 9050, 8118,
            # IoT and embedded
            1883, 8883, 502, 102, 2404, 44818,
            # Security tools
            4444, 4445, 31337, 12345, 54321,
            # Backup and sync
            873, 514, 6000, 7000,
            # Printing and sharing
            631, 515, 9100, 427,
            # Media and streaming
            1755, 554, 8554, 1935, 7001,
            # Enterprise applications
            1521, 1526, 1630, 3050, 5060, 5061
        ]
        
        # Service fingerprints for better detection
        self.service_banners = {
            21: ['FTP', 'FileZilla', 'ProFTPD', 'vsftpd'],
            22: ['SSH', 'OpenSSH', 'Dropbear'],
            23: ['Telnet'],
            25: ['SMTP', 'Postfix', 'Sendmail', 'Exchange'],
            53: ['DNS', 'BIND', 'dnsmasq'],
            80: ['HTTP', 'Apache', 'nginx', 'IIS', 'lighttpd'],
            110: ['POP3'],
            135: ['RPC', 'DCE-RPC'],
            139: ['NetBIOS'],
            143: ['IMAP'],
            389: ['LDAP'],
            443: ['HTTPS', 'Apache', 'nginx', 'IIS'],
            445: ['SMB', 'Samba'],
            993: ['IMAPS'],
            995: ['POP3S'],
            1433: ['MSSQL'],
            1521: ['Oracle'],
            3306: ['MySQL', 'MariaDB'],
            3389: ['RDP', 'Terminal Services'],
            5432: ['PostgreSQL'],
            5900: ['VNC'],
            6379: ['Redis'],
            8080: ['HTTP-Proxy', 'Tomcat', 'Jetty'],
            27017: ['MongoDB']
        }
    
    def create_raw_socket(self):
        """Create raw socket for advanced scanning"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            return sock
        except PermissionError:
            return None
    
    def is_host_alive(self, host):
        """Enhanced host discovery using multiple methods"""
        methods = ['ping', 'tcp_ping', 'arp']
        
        for method in methods:
            if method == 'ping':
                try:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(host)], 
                                          capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        return True
                except:
                    continue
            
            elif method == 'tcp_ping':
                # Try TCP ping on common ports
                for port in [80, 443, 22, 21, 23]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((str(host), port))
                        sock.close()
                        if result == 0:
                            return True
                    except:
                        continue
            
            elif method == 'arp':
                # ARP discovery for local network
                try:
                    result = subprocess.run(['arp', '-n', str(host)], 
                                          capture_output=True, text=True, timeout=1)
                    if '(incomplete)' not in result.stdout and result.returncode == 0:
                        return True
                except:
                    continue
        
        return False
    
    def grab_banner(self, host, port):
        """Grab service banner for identification"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((str(host), port))
            
            # Send appropriate probes based on port
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + str(host).encode() + b'\r\n\r\n')
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                sock.send(b'EHLO test\r\n')
            elif port == 110:
                pass  # POP3 sends banner automatically
            elif port == 143:
                pass  # IMAP sends banner automatically
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100]  # Limit banner length
        except:
            return ""
    
    def scan_port_tcp(self, host, port):
        """Enhanced TCP port scanning with banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(host), port))
            
            if result == 0:
                banner = self.grab_banner(host, port)
                sock.close()
                return {'status': 'open', 'banner': banner}
            else:
                sock.close()
                return {'status': 'closed', 'banner': ''}
        except:
            return {'status': 'filtered', 'banner': ''}
    
    def scan_port_udp(self, host, port):
        """UDP port scanning"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send UDP probe
            if port == 53:  # DNS
                probe = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            elif port == 123:  # NTP
                probe = b'\x1b' + b'\x00' * 47
            elif port == 161:  # SNMP
                probe = b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
            else:
                probe = b'\x00' * 8
            
            sock.sendto(probe, (str(host), port))
            
            # Use select for timeout
            ready = select.select([sock], [], [], self.timeout)
            if ready[0]:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return {'status': 'open', 'banner': ''}
            else:
                sock.close()
                return {'status': 'open|filtered', 'banner': ''}
        except socket.error:
            return {'status': 'closed', 'banner': ''}
        except:
            return {'status': 'filtered', 'banner': ''}
    
    def scan_port(self, host, port):
        """Main port scanning function"""
        if self.scan_type == 'udp':
            return self.scan_port_udp(host, port)
        else:
            return self.scan_port_tcp(host, port)
    
    def get_service_info(self, port, banner=""):
        """Enhanced service detection"""
        try:
            service_name = socket.getservbyport(port)
        except:
            service_name = "unknown"
        
        # Enhanced service detection based on banner
        if banner:
            banner_lower = banner.lower()
            if 'apache' in banner_lower:
                service_name = 'Apache HTTP'
            elif 'nginx' in banner_lower:
                service_name = 'nginx HTTP'
            elif 'microsoft-iis' in banner_lower:
                service_name = 'Microsoft IIS'
            elif 'openssh' in banner_lower:
                service_name = 'OpenSSH'
            elif 'mysql' in banner_lower:
                service_name = 'MySQL'
            elif 'postgresql' in banner_lower:
                service_name = 'PostgreSQL'
            elif 'mongodb' in banner_lower:
                service_name = 'MongoDB'
            elif 'redis' in banner_lower:
                service_name = 'Redis'
        
        return service_name
    
    def detect_os(self, host, open_ports):
        """Basic OS detection based on open ports and TTL"""
        os_hints = []
        
        # Port-based OS detection
        port_numbers = [p['port'] for p in open_ports]
        
        if 3389 in port_numbers or 445 in port_numbers or 135 in port_numbers:
            os_hints.append("Windows")
        if 22 in port_numbers and 80 in port_numbers:
            os_hints.append("Linux/Unix")
        if 548 in port_numbers or 5900 in port_numbers:
            os_hints.append("macOS")
        
        # TTL-based detection
        try:
            result = subprocess.run(['ping', '-c', '1', str(host)], 
                                  capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if ttl <= 64:
                        os_hints.append("Linux/Unix (TTL: {})".format(ttl))
                    elif ttl <= 128:
                        os_hints.append("Windows (TTL: {})".format(ttl))
                    elif ttl <= 255:
                        os_hints.append("Cisco/Network Device (TTL: {})".format(ttl))
        except:
            pass
        
        return list(set(os_hints)) if os_hints else ["Unknown"]
    
    def scan_host(self, host, ports):
        """Comprehensive host scanning"""
        host_ip = str(host)
        
        # Skip host discovery for single host scans or when explicitly disabled
        if len(ports) < 100:  # For targeted scans, always scan regardless of ping
            is_alive = True
        else:
            is_alive = self.is_host_alive(host_ip)
            if not is_alive:
                return host_ip, {
                    'alive': False, 
                    'open_ports': [], 
                    'closed_ports': [],
                    'filtered_ports': [],
                    'os_detection': [],
                    'scan_time': 0
                }
        
        start_time = time.time()
        open_ports = []
        closed_ports = []
        filtered_ports = []
        
        print(f"[*] Scanning {host_ip} ({len(ports)} ports)...")
        
        # Use more threads for individual host scanning
        max_workers = min(len(ports), 200)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, host_ip, port): port 
                             for port in ports}
            
            completed = 0
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                # Progress indicator for large scans
                if len(ports) > 1000 and completed % 1000 == 0:
                    print(f"    Progress: {completed}/{len(ports)} ports scanned")
                
                try:
                    result = future.result()
                    service = self.get_service_info(port, result.get('banner', ''))
                    
                    port_info = {
                        'port': port,
                        'service': service,
                        'banner': result.get('banner', '').replace('\r', '').replace('\n', ' ')[:100]
                    }
                    
                    if result['status'] == 'open':
                        open_ports.append(port_info)
                    elif result['status'] in ['closed']:
                        closed_ports.append(port)
                    else:  # filtered, open|filtered
                        filtered_ports.append(port)
                        
                except Exception as e:
                    filtered_ports.append(port)
        
        scan_time = time.time() - start_time
        
        # OS detection for hosts with open ports
        os_detection = []
        if open_ports:
            os_detection = self.detect_os(host_ip, open_ports)
        
        return host_ip, {
            'alive': True,
            'open_ports': sorted(open_ports, key=lambda x: x['port']),
            'closed_ports': sorted(closed_ports),
            'filtered_ports': sorted(filtered_ports),
            'os_detection': os_detection,
            'scan_time': scan_time
        }
    
    def scan_network(self, network, ports=None):
        """Enhanced network scanning"""
        if ports is None:
            ports = self.common_ports
        
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            print(f"[-] Invalid network format: {network}")
            return
        
        hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
        
        print(f"[+] Starting advanced network scan for {network}")
        print(f"[+] Targets: {len(hosts)} hosts")
        print(f"[+] Ports per host: {len(ports)}")
        print(f"[+] Scan type: {self.scan_type.upper()}")
        print(f"[+] Threads: {self.max_threads}")
        print(f"[+] Estimated time: {(len(hosts) * len(ports) * self.timeout) / self.max_threads:.1f} seconds")
        print("=" * 70)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(hosts))) as executor:
            future_to_host = {executor.submit(self.scan_host, host, ports): host 
                             for host in hosts}
            
            completed_hosts = 0
            for future in as_completed(future_to_host):
                original_host = future_to_host[future]
                completed_hosts += 1
                
                try:
                    host_ip, result = future.result()
                    with self.lock:
                        self.results[host_ip] = result
                        
                    if result['alive']:
                        open_count = len(result['open_ports'])
                        if open_count > 0:
                            print(f"[+] {host_ip:<15} - {open_count:>3} open ports "
                                  f"({result['scan_time']:.1f}s)")
                        else:
                            print(f"[-] {host_ip:<15} - No open ports found")
                    else:
                        print(f"[-] {host_ip:<15} - Host unreachable")
                        
                    # Progress for large networks
                    if len(hosts) > 50 and completed_hosts % 10 == 0:
                        print(f"    [{completed_hosts}/{len(hosts)}] hosts completed...")
                        
                except Exception as e:
                    print(f"[!] Error scanning {original_host}: {e}")
        
        total_time = time.time() - start_time
        print(f"\n[+] Network scan completed in {total_time:.2f} seconds")
    
    def print_results(self, show_closed=False, show_filtered=False):
        """Enhanced results display"""
        alive_hosts = 0
        total_open_ports = 0
        total_filtered_ports = 0
        
        print("\n" + "="*90)
        print("COMPREHENSIVE SCAN RESULTS")
        print("="*90)
        
        # Sort results by IP address
        sorted_results = sorted(self.results.items(), 
                               key=lambda x: ipaddress.ip_address(x[0]))
        
        for host, data in sorted_results:
            if not data['alive']:
                continue
                
            alive_hosts += 1
            open_ports = data['open_ports']
            closed_ports = data['closed_ports']
            filtered_ports = data['filtered_ports']
            os_info = data.get('os_detection', [])
            scan_time = data.get('scan_time', 0)
            
            total_open_ports += len(open_ports)
            total_filtered_ports += len(filtered_ports)
            
            print(f"\n┌─ Host: {host}")
            print(f"├─ Status: ALIVE")
            print(f"├─ Scan time: {scan_time:.2f}s")
            print(f"├─ Open ports: {len(open_ports)}")
            print(f"├─ Closed ports: {len(closed_ports)}")
            print(f"├─ Filtered ports: {len(filtered_ports)}")
            if os_info:
                print(f"├─ OS Detection: {', '.join(os_info)}")
            
            if open_ports:
                print("├─ Open Ports Details:")
                for port_info in open_ports:
                    banner_info = f" - {port_info['banner']}" if port_info['banner'] else ""
                    print(f"│  ├─ {port_info['port']:>5}/tcp │ {port_info['service']:<20}{banner_info}")
            
            if show_closed and closed_ports:
                if len(closed_ports) <= 20:
                    print(f"├─ Closed ports: {', '.join(map(str, closed_ports))}")
                else:
                    print(f"├─ Closed ports: {len(closed_ports)} ports (use --show-closed for details)")
            
            if show_filtered and filtered_ports:
                if len(filtered_ports) <= 20:
                    print(f"├─ Filtered ports: {', '.join(map(str, filtered_ports))}")
                else:
                    print(f"├─ Filtered ports: {len(filtered_ports)} ports")
            
            print("└" + "─" * 60)
        
        # Enhanced summary
        dead_hosts = len(self.results) - alive_hosts
        print(f"\n📊 SCAN SUMMARY:")
        print(f"   Total hosts scanned: {len(self.results)}")
        print(f"   Alive hosts: {alive_hosts}")
        print(f"   Dead/filtered hosts: {dead_hosts}")
        print(f"   Total open ports: {total_open_ports}")
        print(f"   Total filtered ports: {total_filtered_ports}")
        
        # Top services found
        if total_open_ports > 0:
            service_count = {}
            for host_data in self.results.values():
                for port in host_data.get('open_ports', []):
                    service = port['service']
                    service_count[service] = service_count.get(service, 0) + 1
            
            print(f"\n🔍 TOP SERVICES FOUND:")
            for service, count in sorted(service_count.items(), 
                                       key=lambda x: x[1], reverse=True)[:10]:
                print(f"   {service}: {count} instances")
    
    def save_results(self, filename, format='txt'):
        """Save results in multiple formats"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if format == 'json':
            # Save as JSON
            json_data = {
                'scan_info': {
                    'timestamp': timestamp,
                    'scan_type': self.scan_type,
                    'total_hosts': len(self.results)
                },
                'results': self.results
            }
            with open(filename, 'w') as f:
                json.dump(json_data, f, indent=2)
        
        else:
            # Save as text
            with open(filename, 'w') as f:
                f.write(f"Advanced Network Port Scan Results\n")
                f.write(f"Generated: {timestamp}\n")
                f.write(f"Scan Type: {self.scan_type.upper()}\n")
                f.write("="*80 + "\n\n")
                
                for host, data in sorted(self.results.items()):
                    if not data['alive']:
                        continue
                        
                    f.write(f"Host: {host}\n")
                    f.write(f"Status: ALIVE\n")
                    f.write(f"Scan time: {data.get('scan_time', 0):.2f}s\n")
                    f.write(f"Open ports: {len(data['open_ports'])}\n")
                    f.write(f"Closed ports: {len(data['closed_ports'])}\n")
                    f.write(f"Filtered ports: {len(data['filtered_ports'])}\n")
                    
                    if data.get('os_detection'):
                        f.write(f"OS Detection: {', '.join(data['os_detection'])}\n")
                    
                    if data['open_ports']:
                        f.write("Open ports details:\n")
                        for port_info in data['open_ports']:
                            banner = f" - {port_info['banner']}" if port_info['banner'] else ""
                            f.write(f"  {port_info['port']}/tcp - {port_info['service']}{banner}\n")
                    
                    f.write("-" * 60 + "\n")
        
        print(f"[+] Results saved to {filename}")

def parse_ports(port_string):
    """Enhanced port parsing with named ranges"""
    if port_string.lower() == 'all':
        return list(range(1, 65536))
    elif port_string.lower() == 'common':
        scanner = AdvancedPortScanner()
        return scanner.common_ports
    elif port_string.lower() == 'well-known':
        return list(range(1, 1024))
    
    ports = []
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            except ValueError:
                print(f"[-] Invalid port range: {part}")
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                print(f"[-] Invalid port: {part}")
                continue
    return list(set(ports))  # Remove duplicates

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Network Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1                          # Scan common ports
  %(prog)s 192.168.1.0/24 -p 1-1000            # Scan port range on network
  %(prog)s target.com -p all                   # Scan all 65535 ports
  %(prog)s 10.0.0.1 -p common --show-closed    # Show closed ports too
  %(prog)s 192.168.1.1 -p 80,443,22,21 -t 5   # Custom ports with timeout
  %(prog)s 192.168.1.0/24 --udp -p 53,161,123 # UDP scan
        """
    )
    
    parser.add_argument('target', help='Target host or network (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='common',
                       help='Ports to scan: "common", "all", "well-known", or custom (e.g., 21,22,80 or 1-1000)')
    parser.add_argument('-t', '--timeout', type=float, default=3,
                       help='Connection timeout in seconds (default: 3)')
    parser.add_argument('--threads', type=int, default=500,
                       help='Maximum threads (default: 500)')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('--format', choices=['txt', 'json'], default='txt',
                       help='Output format (default: txt)')
    parser.add_argument('--show-closed', action='store_true',
                       help='Show closed ports in results')
    parser.add_argument('--show-filtered', action='store_true',
                       help='Show filtered ports in results')
    parser.add_argument('--udp', action='store_true',
                       help='Perform UDP scan instead of TCP')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Banner
    print("""
    ╔═══════════════════════════════════════════════╗
    ║        Advanced Network Port Scanner          ║
    ║              Powerful & Stealthy              ║
    ╚═══════════════════════════════════════════════╝
    """)
    
    # Check permissions for advanced features
    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. Some advanced features may be limited.")
        print("    For full functionality, run with: sudo python3 port_scanner.py")
    
    # Initialize scanner
    scan_type = 'udp' if args.udp else 'tcp'
    scanner = AdvancedPortScanner(
        timeout=args.timeout, 
        max_threads=args.threads,
        scan_type=scan_type
    )
    
    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        print("[-] No valid ports specified!")
        sys.exit(1)
    
    print(f"[+] Target: {args.target}")
    print(f"[+] Ports: {len(ports)} ports")
    print(f"[+] Scan type: {scan_type.upper()}")
    print(f"[+] Timeout: {args.timeout}s")
    print(f"[+] Threads: {args.threads}")
    
    try:
        # Determine scan type
        if '/' in args.target:
            scanner.scan_network(args.target, ports)
        else:
            # Single host scan
            print(f"\n[+] Scanning single host: {args.target}")
            host_ip, result = scanner.scan_host(args.target, ports)
            scanner.results[host_ip] = result
        
        # Display results
        scanner.print_results(
            show_closed=args.show_closed,
            show_filtered=args.show_filtered
        )
        
        # Save results if requested
        if args.output:
            scanner.save_results(args.output, args.format)
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
