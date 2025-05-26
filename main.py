#!/usr/bin/env python3
"""
NetPulse Elite - Real-time Network Analysis Platform
Advanced real-time network monitoring and analysis tool
Focus: Network performance, topology, and technical metrics
"""

import asyncio
import threading
import time
import sys
import os
import socket
import struct
import subprocess
import platform
import json
import statistics
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
import argparse
import curses
import signal

# Network libraries
import psutil
import netifaces
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
import requests
import numpy as np

# Terminal colors for non-curses output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLINK = '\033[5m'
    RESET = '\033[0m'
    CLEAR_LINE = '\033[K'
    CLEAR_SCREEN = '\033[2J'
    HOME = '\033[H'

@dataclass
class NetworkInterface:
    name: str
    ip_addresses: List[str]
    mac_address: str
    status: str
    mtu: int
    speed: int
    duplex: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int
    tx_errors: int
    rx_dropped: int
    tx_dropped: int
    timestamp: datetime

@dataclass
class NetworkDevice:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    ports: List[int] = field(default_factory=list)
    response_time: float = 0.0
    last_seen: datetime = field(default_factory=datetime.now)
    device_type: str = "unknown"
    os_guess: str = ""

@dataclass
class TrafficMetrics:
    timestamp: datetime
    interface: str
    bytes_per_sec: float
    packets_per_sec: float
    bandwidth_utilization: float
    protocol_distribution: Dict[str, int]
    top_talkers: List[Tuple[str, int]]
    connection_count: int
    error_rate: float

@dataclass
class NetworkRoute:
    destination: str
    gateway: str
    interface: str
    metric: int
    flags: str

@dataclass
class NetworkQuality:
    timestamp: datetime
    target: str
    latency_avg: float
    latency_min: float
    latency_max: float
    latency_stddev: float
    jitter: float
    packet_loss: float
    throughput_mbps: float
    dns_resolution_time: float

@dataclass
class NetworkTopology:
    local_networks: List[str]
    gateway: str
    dns_servers: List[str]
    discovered_devices: List[NetworkDevice]
    network_segments: Dict[str, List[str]]
    routing_table: List[NetworkRoute]

class RealTimeNetworkAnalyzer:
    def __init__(self):
        self.running = False
        self.interfaces = {}
        self.traffic_history = defaultdict(lambda: deque(maxlen=300))  # 5 minutes at 1sec intervals
        self.devices = {}
        self.network_quality = {}
        self.packet_capture_stats = defaultdict(int)
        self.bandwidth_usage = defaultdict(lambda: deque(maxlen=60))  # 1 minute history
        self.connection_tracker = defaultdict(set)
        self.dns_cache = {}
        self.topology = None
        
        # Performance counters
        self.last_interface_stats = {}
        self.start_time = time.time()
        
        # Real-time display
        self.display_mode = "dashboard"  # dashboard, interfaces, traffic, topology, quality
        self.update_interval = 1.0
        
    async def start_analysis(self, interface=None, display_mode="dashboard"):
        """Start real-time network analysis"""
        self.display_mode = display_mode
        self.running = True
        
        print(f"{Colors.CYAN}🚀 NetPulse Elite - Real-time Network Analysis{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
        
        # Initialize network topology
        await self.discover_network_topology()
        
        # Start monitoring tasks
        tasks = [
            asyncio.create_task(self.monitor_interfaces()),
            asyncio.create_task(self.monitor_traffic(interface)),
            asyncio.create_task(self.monitor_network_quality()),
            asyncio.create_task(self.discover_devices()),
            asyncio.create_task(self.display_real_time_stats()),
            asyncio.create_task(self.monitor_connections())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{Colors.YELLOW}Shutting down network analysis...{Colors.RESET}")

    async def discover_network_topology(self):
        """Discover local network topology"""
        print(f"{Colors.CYAN}🔍 Discovering network topology...{Colors.RESET}")
        
        local_networks = []
        gateway = None
        dns_servers = []
        routing_table = []
        
        try:
            # Get default gateway
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                gateway = gateways['default'][netifaces.AF_INET][0]
            
            # Get local networks
            for interface in netifaces.interfaces():
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            ip = addr_info.get('addr')
                            netmask = addr_info.get('netmask')
                            if ip and netmask and not ip.startswith('127.'):
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                local_networks.append(str(network.network_address) + '/' + str(network.prefixlen))
                except:
                    continue
            
            # Get DNS servers
            try:
                if platform.system() == "Windows":
                    import winreg
                    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                    key = winreg.OpenKey(reg, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
                    dns_servers = winreg.QueryValueEx(key, "NameServer")[0].split()
                else:
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                dns_servers.append(line.split()[1])
            except:
                dns_servers = ['8.8.8.8', '1.1.1.1']  # Fallback
            
            # Get routing table
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(['route', 'print'], capture_output=True, text=True)
                else:
                    result = subprocess.run(['route', '-n'], capture_output=True, text=True)
                
                # Parse routing table (simplified)
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] != 'Destination':
                        try:
                            route = NetworkRoute(
                                destination=parts[0],
                                gateway=parts[1] if len(parts) > 1 else '',
                                interface=parts[-1] if len(parts) > 2 else '',
                                metric=int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                                flags=parts[3] if len(parts) > 3 else ''
                            )
                            routing_table.append(route)
                        except:
                            continue
            except:
                pass
            
            self.topology = NetworkTopology(
                local_networks=local_networks,
                gateway=gateway or "Unknown",
                dns_servers=dns_servers,
                discovered_devices=[],
                network_segments={},
                routing_table=routing_table
            )
            
        except Exception as e:
            print(f"{Colors.RED}Error discovering topology: {e}{Colors.RESET}")

    async def monitor_interfaces(self):
        """Monitor network interfaces in real-time"""
        while self.running:
            try:
                current_interfaces = {}
                
                for interface_name in psutil.net_if_addrs().keys():
                    try:
                        # Get interface addresses
                        addrs = psutil.net_if_addrs()[interface_name]
                        stats = psutil.net_if_stats()[interface_name]
                        io_stats = psutil.net_io_counters(pernic=True).get(interface_name)
                        
                        ip_addresses = []
                        mac_address = ""
                        
                        for addr in addrs:
                            if addr.family == socket.AF_INET:
                                ip_addresses.append(addr.address)
                            elif addr.family == psutil.AF_LINK:
                                mac_address = addr.address
                        
                        if not ip_addresses and not mac_address:
                            continue
                        
                        interface = NetworkInterface(
                            name=interface_name,
                            ip_addresses=ip_addresses,
                            mac_address=mac_address,
                            status="up" if stats.isup else "down",
                            mtu=stats.mtu,
                            speed=stats.speed,
                            duplex=stats.duplex.name if stats.duplex else "unknown",
                            rx_bytes=io_stats.bytes_recv if io_stats else 0,
                            tx_bytes=io_stats.bytes_sent if io_stats else 0,
                            rx_packets=io_stats.packets_recv if io_stats else 0,
                            tx_packets=io_stats.packets_sent if io_stats else 0,
                            rx_errors=io_stats.errin if io_stats else 0,
                            tx_errors=io_stats.errout if io_stats else 0,
                            rx_dropped=io_stats.dropin if io_stats else 0,
                            tx_dropped=io_stats.dropout if io_stats else 0,
                            timestamp=datetime.now()
                        )
                        
                        current_interfaces[interface_name] = interface
                        
                        # Calculate traffic rates
                        if interface_name in self.last_interface_stats:
                            prev = self.last_interface_stats[interface_name]
                            time_delta = (interface.timestamp - prev.timestamp).total_seconds()
                            
                            if time_delta > 0:
                                rx_rate = (interface.rx_bytes - prev.rx_bytes) / time_delta
                                tx_rate = (interface.tx_bytes - prev.tx_bytes) / time_delta
                                
                                # Calculate bandwidth utilization
                                total_rate = rx_rate + tx_rate
                                max_bandwidth = interface.speed * 1024 * 1024 / 8 if interface.speed > 0 else 0
                                utilization = (total_rate / max_bandwidth * 100) if max_bandwidth > 0 else 0
                                
                                # Store traffic metrics
                                metrics = TrafficMetrics(
                                    timestamp=datetime.now(),
                                    interface=interface_name,
                                    bytes_per_sec=total_rate,
                                    packets_per_sec=(interface.rx_packets + interface.tx_packets - 
                                                   prev.rx_packets - prev.tx_packets) / time_delta,
                                    bandwidth_utilization=min(utilization, 100),
                                    protocol_distribution={},
                                    top_talkers=[],
                                    connection_count=0,
                                    error_rate=((interface.rx_errors + interface.tx_errors - 
                                               prev.rx_errors - prev.tx_errors) / 
                                              max(1, interface.rx_packets + interface.tx_packets - 
                                                  prev.rx_packets - prev.tx_packets)) * 100
                                )
                                
                                self.traffic_history[interface_name].append(metrics)
                                self.bandwidth_usage[interface_name].append({
                                    'timestamp': time.time(),
                                    'rx_rate': rx_rate,
                                    'tx_rate': tx_rate,
                                    'utilization': utilization
                                })
                    
                    except Exception as e:
                        continue
                
                self.interfaces = current_interfaces
                self.last_interface_stats = current_interfaces.copy()
                
                await asyncio.sleep(self.update_interval)
                
            except Exception as e:
                print(f"Interface monitoring error: {e}")
                await asyncio.sleep(1)

    async def monitor_traffic(self, interface=None):
        """Monitor network traffic using packet capture"""
        if not interface:
            # Use default interface
            default_routes = psutil.net_if_stats()
            interface = next((name for name, stats in default_routes.items() 
                            if stats.isup and name != 'lo'), None)
        
        if not interface:
            return
        
        def packet_handler(packet):
            try:
                self.packet_capture_stats['total'] += 1
                
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Protocol analysis
                    if packet.haslayer(TCP):
                        self.packet_capture_stats['tcp'] += 1
                        # Track connections
                        connection = (src_ip, packet[TCP].sport, dst_ip, packet[TCP].dport)
                        self.connection_tracker[interface].add(connection)
                    elif packet.haslayer(UDP):
                        self.packet_capture_stats['udp'] += 1
                    elif packet.haslayer(ICMP):
                        self.packet_capture_stats['icmp'] += 1
                    
                    # Traffic analysis
                    packet_size = len(packet)
                    timestamp = time.time()
                    
                    # Update bandwidth usage
                    if len(self.bandwidth_usage[interface]) > 0:
                        self.bandwidth_usage[interface][-1]['packet_count'] = \
                            self.bandwidth_usage[interface][-1].get('packet_count', 0) + 1
                        self.bandwidth_usage[interface][-1]['total_bytes'] = \
                            self.bandwidth_usage[interface][-1].get('total_bytes', 0) + packet_size
                
            except Exception as e:
                pass
        
        try:
            # Start packet capture in background thread
            def capture_packets():
                scapy.sniff(
                    iface=interface,
                    prn=packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            
            capture_thread = threading.Thread(target=capture_packets, daemon=True)
            capture_thread.start()
            
        except Exception as e:
            print(f"{Colors.RED}Packet capture error: {e}{Colors.RESET}")

    async def monitor_network_quality(self):
        """Monitor network quality metrics"""
        targets = ['8.8.8.8', '1.1.1.1', 'google.com']
        
        while self.running:
            try:
                for target in targets:
                    # Ping test
                    latencies = []
                    packet_loss = 0
                    
                    for i in range(5):
                        start_time = time.time()
                        try:
                            if platform.system() == "Windows":
                                result = subprocess.run(
                                    ['ping', '-n', '1', '-w', '1000', target],
                                    capture_output=True, text=True, timeout=2
                                )
                            else:
                                result = subprocess.run(
                                    ['ping', '-c', '1', '-W', '1', target],
                                    capture_output=True, text=True, timeout=2
                                )
                            
                            if result.returncode == 0:
                                latency = (time.time() - start_time) * 1000
                                latencies.append(latency)
                            else:
                                packet_loss += 1
                                
                        except Exception:
                            packet_loss += 1
                        
                        await asyncio.sleep(0.2)
                    
                    # DNS resolution test
                    dns_start = time.time()
                    try:
                        socket.gethostbyname(target)
                        dns_time = (time.time() - dns_start) * 1000
                    except:
                        dns_time = -1
                    
                    # Calculate quality metrics
                    if latencies:
                        quality = NetworkQuality(
                            timestamp=datetime.now(),
                            target=target,
                            latency_avg=statistics.mean(latencies),
                            latency_min=min(latencies),
                            latency_max=max(latencies),
                            latency_stddev=statistics.stdev(latencies) if len(latencies) > 1 else 0,
                            jitter=statistics.stdev(latencies) if len(latencies) > 1 else 0,
                            packet_loss=(packet_loss / 5) * 100,
                            throughput_mbps=0,  # Would need separate test
                            dns_resolution_time=dns_time
                        )
                        
                        self.network_quality[target] = quality
                
                await asyncio.sleep(10)  # Test every 10 seconds
                
            except Exception as e:
                print(f"Quality monitoring error: {e}")
                await asyncio.sleep(5)

    async def discover_devices(self):
        """Discover devices on local network"""
        while self.running:
            try:
                if not self.topology or not self.topology.local_networks:
                    await asyncio.sleep(30)
                    continue
                
                discovered = []
                
                for network_str in self.topology.local_networks:
                    try:
                        network = ipaddress.IPv4Network(network_str, strict=False)
                        
                        # ARP scan for active devices
                        arp_request = scapy.ARP(pdst=str(network))
                        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                        arp_request_broadcast = broadcast / arp_request
                        
                        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
                        
                        for element in answered_list:
                            device_ip = element[1].psrc
                            device_mac = element[1].hwsrc
                            
                            # Try to get hostname
                            hostname = ""
                            try:
                                hostname = socket.gethostbyaddr(device_ip)[0]
                            except:
                                pass
                            
                            # Determine vendor from MAC
                            vendor = self.get_vendor_from_mac(device_mac)
                            
                            device = NetworkDevice(
                                ip=device_ip,
                                mac=device_mac,
                                hostname=hostname,
                                vendor=vendor,
                                last_seen=datetime.now(),
                                response_time=0.0
                            )
                            
                            discovered.append(device)
                            self.devices[device_ip] = device
                    
                    except Exception as e:
                        continue
                
                if self.topology:
                    self.topology.discovered_devices = discovered
                
                await asyncio.sleep(60)  # Scan every minute
                
            except Exception as e:
                print(f"Device discovery error: {e}")
                await asyncio.sleep(30)

    async def monitor_connections(self):
        """Monitor active network connections"""
        while self.running:
            try:
                connections = psutil.net_connections(kind='inet')
                
                # Analyze connections by interface
                for interface in self.interfaces:
                    active_connections = [
                        conn for conn in connections 
                        if conn.status == 'ESTABLISHED'
                    ]
                    
                    # Update traffic metrics with connection count
                    if self.traffic_history[interface]:
                        self.traffic_history[interface][-1].connection_count = len(active_connections)
                
                await asyncio.sleep(5)
                
            except Exception as e:
                await asyncio.sleep(5)

    def get_vendor_from_mac(self, mac_address):
        """Get vendor from MAC address (simplified OUI lookup)"""
        oui_db = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:0C:29': 'VMware',
            '00:1B:21': 'Intel',
            '00:15:5D': 'Microsoft',
            '52:54:00': 'QEMU',
        }
        
        oui = mac_address[:8].upper()
        return oui_db.get(oui, 'Unknown')

    async def display_real_time_stats(self):
        """Display real-time statistics"""
        while self.running:
            try:
                if self.display_mode == "dashboard":
                    self.display_dashboard()
                elif self.display_mode == "interfaces":
                    self.display_interfaces()
                elif self.display_mode == "traffic":
                    self.display_traffic()
                elif self.display_mode == "topology":
                    self.display_topology()
                elif self.display_mode == "quality":
                    self.display_quality()
                
                await asyncio.sleep(self.update_interval)
                
            except Exception as e:
                print(f"Display error: {e}")
                await asyncio.sleep(1)

    def display_dashboard(self):
        """Display main dashboard"""
        # Clear screen and move to top
        print(f"{Colors.CLEAR_SCREEN}{Colors.HOME}", end='')
        
        # Header
        uptime = timedelta(seconds=int(time.time() - self.start_time))
        print(f"{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Real-time Network Dashboard{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
        print(f"Uptime: {uptime} | Update: {datetime.now().strftime('%H:%M:%S')} | Mode: Dashboard")
        print()
        
        # Network Overview
        print(f"{Colors.BOLD}🌐 Network Overview{Colors.RESET}")
        if self.topology:
            print(f"  Gateway: {Colors.GREEN}{self.topology.gateway}{Colors.RESET}")
            print(f"  Networks: {Colors.CYAN}{', '.join(self.topology.local_networks[:3])}{Colors.RESET}")
            print(f"  DNS: {Colors.CYAN}{', '.join(self.topology.dns_servers[:2])}{Colors.RESET}")
            print(f"  Devices: {Colors.YELLOW}{len(self.topology.discovered_devices)}{Colors.RESET}")
        print()
        
        # Interface Status
        print(f"{Colors.BOLD}🔌 Interface Status{Colors.RESET}")
        for name, interface in list(self.interfaces.items())[:4]:
            status_color = Colors.GREEN if interface.status == "up" else Colors.RED
            utilization = 0
            if self.bandwidth_usage[name]:
                utilization = self.bandwidth_usage[name][-1].get('utilization', 0)
            
            print(f"  {name:<12} {status_color}{interface.status:<4}{Colors.RESET} "
                  f"{', '.join(interface.ip_addresses[:1]):<15} "
                  f"Util: {utilization:5.1f}% "
                  f"Speed: {interface.speed} Mbps")
        print()
        
        # Traffic Summary
        print(f"{Colors.BOLD}📊 Traffic Summary{Colors.RESET}")
        total_rx = sum(i.rx_bytes for i in self.interfaces.values())
        total_tx = sum(i.tx_bytes for i in self.interfaces.values())
        total_packets = sum(i.rx_packets + i.tx_packets for i in self.interfaces.values())
        
        print(f"  Total RX: {Colors.GREEN}{self.format_bytes(total_rx)}{Colors.RESET}")
        print(f"  Total TX: {Colors.YELLOW}{self.format_bytes(total_tx)}{Colors.RESET}")
        print(f"  Packets:  {Colors.CYAN}{total_packets:,}{Colors.RESET}")
        print(f"  Protocols: TCP:{self.packet_capture_stats.get('tcp', 0)} "
              f"UDP:{self.packet_capture_stats.get('udp', 0)} "
              f"ICMP:{self.packet_capture_stats.get('icmp', 0)}")
        print()
        
        # Network Quality
        print(f"{Colors.BOLD}🚀 Network Quality{Colors.RESET}")
        for target, quality in list(self.network_quality.items())[:3]:
            latency_color = Colors.GREEN if quality.latency_avg < 50 else Colors.YELLOW if quality.latency_avg < 100 else Colors.RED
            loss_color = Colors.GREEN if quality.packet_loss == 0 else Colors.RED
            
            print(f"  {target:<12} Latency: {latency_color}{quality.latency_avg:5.1f}ms{Colors.RESET} "
                  f"Loss: {loss_color}{quality.packet_loss:4.1f}%{Colors.RESET} "
                  f"Jitter: {quality.jitter:5.1f}ms")
        
        print(f"\n{Colors.DIM}Press Ctrl+C to exit | Commands: i=interfaces, t=traffic, n=topology, q=quality{Colors.RESET}")

    def display_interfaces(self):
        """Display detailed interface information"""
        print(f"{Colors.CLEAR_SCREEN}{Colors.HOME}", end='')
        
        print(f"{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Network Interfaces{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*90}{Colors.RESET}")
        print(f"Update: {datetime.now().strftime('%H:%M:%S')} | Mode: Interfaces")
        print()
        
        for name, interface in self.interfaces.items():
            status_color = Colors.GREEN if interface.status == "up" else Colors.RED
            
            print(f"{Colors.BOLD}{name}{Colors.RESET} ({status_color}{interface.status}{Colors.RESET})")
            print(f"  MAC: {interface.mac_address}")
            print(f"  IPs: {', '.join(interface.ip_addresses)}")
            print(f"  MTU: {interface.mtu} | Speed: {interface.speed} Mbps | Duplex: {interface.duplex}")
            
            # Traffic stats
            rx_rate = tx_rate = 0
            if self.bandwidth_usage[name]:
                latest = self.bandwidth_usage[name][-1]
                rx_rate = latest.get('rx_rate', 0)
                tx_rate = latest.get('tx_rate', 0)
            
            print(f"  RX: {self.format_bytes(interface.rx_bytes)} "
                  f"({interface.rx_packets:,} packets, {interface.rx_errors} errors)")
            print(f"  TX: {self.format_bytes(interface.tx_bytes)} "
                  f"({interface.tx_packets:,} packets, {interface.tx_errors} errors)")
            print(f"  Rate: ↓{self.format_bytes(rx_rate)}/s ↑{self.format_bytes(tx_rate)}/s")
            
            # Bandwidth utilization graph
            if self.bandwidth_usage[name]:
                utilization_history = [u.get('utilization', 0) for u in list(self.bandwidth_usage[name])[-20:]]
                graph = self.create_mini_graph(utilization_history, width=40)
                print(f"  Util: {graph}")
            
            print()

    def display_traffic(self):
        """Display traffic analysis"""
        print(f"{Colors.CLEAR_SCREEN}{Colors.HOME}", end='')
        
        print(f"{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Traffic Analysis{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
        print(f"Update: {datetime.now().strftime('%H:%M:%S')} | Mode: Traffic")
        print()
        
        # Protocol distribution
        total_packets = sum(self.packet_capture_stats.values()) or 1
        print(f"{Colors.BOLD}📊 Protocol Distribution{Colors.RESET}")
        print(f"  TCP: {self.packet_capture_stats.get('tcp', 0):,} "
              f"({self.packet_capture_stats.get('tcp', 0)/total_packets*100:.1f}%)")
        print(f"  UDP: {self.packet_capture_stats.get('udp', 0):,} "
              f"({self.packet_capture_stats.get('udp', 0)/total_packets*100:.1f}%)")
        print(f"  ICMP: {self.packet_capture_stats.get('icmp', 0):,} "
              f"({self.packet_capture_stats.get('icmp', 0)/total_packets*100:.1f}%)")
        print(f"  Total: {total_packets:,} packets captured")
        print()
        
        # Bandwidth usage per interface
        print(f"{Colors.BOLD}📈 Bandwidth Usage{Colors.RESET}")
        for interface, metrics_list in self.traffic_history.items():
            if metrics_list:
                latest = metrics_list[-1]
                print(f"  {interface:<12} "
                      f"Rate: {self.format_bytes(latest.bytes_per_sec)}/s "
                      f"Util: {latest.bandwidth_utilization:5.1f}% "
                      f"PPS: {latest.packets_per_sec:6.1f} "
                      f"Errors: {latest.error_rate:4.1f}%")
                
                # Mini bandwidth graph
                rates = [m.bytes_per_sec for m in list(metrics_list)[-30:]]
                if rates:
                    graph = self.create_mini_graph(rates, width=40, normalize=True)
                    print(f"    Rate: {graph}")
        print()
        
        # Active connections
        print(f"{Colors.BOLD}🔗 Active Connections{Colors.RESET}")
        try:
            connections = psutil.net_connections(kind='inet')
            established = [c for c in connections if c.status == 'ESTABLISHED']
            listening = [c for c in connections if c.status == 'LISTEN']
            
            print(f"  Established: {len(established)}")
            print(f"  Listening: {len(listening)}")
            
            # Show top listening ports
            ports = defaultdict(int)
            for conn in listening:
                if conn.laddr:
                    ports[conn.laddr.port] += 1
            
            top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]
            print(f"  Top listening ports: {', '.join(f'{port}({count})' for port, count in top_ports)}")
            
        except Exception as e:
            print(f"  Connection info unavailable: {e}")

    def display_topology(self):
        """Display network topology"""
        print(f"{Colors.CLEAR_SCREEN}{Colors.HOME}", end='')
        
        print(f"{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Network Topology{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
        print(f"Update: {datetime.now().strftime('%H:%M:%S')} | Mode: Topology")
        print()
        
        if not self.topology:
            print("Network topology not available")
            return
        
        # Network segments
        print(f"{Colors.BOLD}🏠 Local Networks{Colors.RESET}")
        for network in self.topology.local_networks:
            print(f"  📍 {network}")
        print()
        
        # Gateway and DNS
        print(f"{Colors.BOLD}🌐 Infrastructure{Colors.RESET}")
        print(f"  Gateway: {Colors.GREEN}{self.topology.gateway}{Colors.RESET}")
        print(f"  DNS Servers:")
        for dns in self.topology.dns_servers:
            print(f"    🔍 {dns}")
        print()
        
        # Discovered devices
        print(f"{Colors.BOLD}📱 Discovered Devices ({len(self.topology.discovered_devices)}){Colors.RESET}")
        for device in self.topology.discovered_devices[:15]:
            device_icon = "🖥️" if "server" in device.hostname.lower() else "📱"
            hostname_display = device.hostname[:20] if device.hostname else "Unknown"
            
            print(f"  {device_icon} {device.ip:<15} {device.mac:<17} "
                  f"{hostname_display:<20} {device.vendor}")
        
        if len(self.topology.discovered_devices) > 15:
            print(f"  ... and {len(self.topology.discovered_devices) - 15} more devices")
        print()
        
        # Routing table (simplified)
        print(f"{Colors.BOLD}🛤️  Routing Table (Top 10){Colors.RESET}")
        for route in self.topology.routing_table[:10]:
            print(f"  {route.destination:<18} via {route.gateway:<15} "
                  f"dev {route.interface:<10} metric {route.metric}")

    def display_quality(self):
        """Display network quality metrics"""
        print(f"{Colors.CLEAR_SCREEN}{Colors.HOME}", end='')
        
        print(f"{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Network Quality{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
        print(f"Update: {datetime.now().strftime('%H:%M:%S')} | Mode: Quality")
        print()
        
        for target, quality in self.network_quality.items():
            # Color coding based on quality
            latency_color = (Colors.GREEN if quality.latency_avg < 50 else 
                           Colors.YELLOW if quality.latency_avg < 100 else Colors.RED)
            loss_color = Colors.GREEN if quality.packet_loss == 0 else Colors.RED
            
            print(f"{Colors.BOLD}🎯 {target}{Colors.RESET}")
            print(f"  Latency: {latency_color}{quality.latency_avg:6.2f}ms{Colors.RESET} "
                  f"(min: {quality.latency_min:.2f}, max: {quality.latency_max:.2f})")
            print(f"  Jitter:  {quality.jitter:6.2f}ms")
            print(f"  Loss:    {loss_color}{quality.packet_loss:6.2f}%{Colors.RESET}")
            if quality.dns_resolution_time > 0:
                dns_color = Colors.GREEN if quality.dns_resolution_time < 100 else Colors.YELLOW
                print(f"  DNS:     {dns_color}{quality.dns_resolution_time:6.2f}ms{Colors.RESET}")
            print(f"  Updated: {quality.timestamp.strftime('%H:%M:%S')}")
            print()
        
        # Quality assessment
        if self.network_quality:
            avg_latency = statistics.mean(q.latency_avg for q in self.network_quality.values())
            avg_loss = statistics.mean(q.packet_loss for q in self.network_quality.values())
            
            print(f"{Colors.BOLD}📊 Overall Assessment{Colors.RESET}")
            
            if avg_latency < 50 and avg_loss < 1:
                quality_rating = f"{Colors.GREEN}Excellent{Colors.RESET}"
            elif avg_latency < 100 and avg_loss < 5:
                quality_rating = f"{Colors.YELLOW}Good{Colors.RESET}"
            else:
                quality_rating = f"{Colors.RED}Poor{Colors.RESET}"
            
            print(f"  Network Quality: {quality_rating}")
            print(f"  Average Latency: {avg_latency:.2f}ms")
            print(f"  Average Loss: {avg_loss:.2f}%")

    def create_mini_graph(self, values, width=40, normalize=False):
        """Create a mini ASCII graph"""
        if not values:
            return "No data"
        
        if normalize:
            max_val = max(values) if max(values) > 0 else 1
            normalized = [v / max_val for v in values]
        else:
            max_val = 100  # Assume percentage
            normalized = [min(v / max_val, 1.0) for v in values]
        
        # Create graph
        graph = ""
        levels = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        
        for value in normalized[-width:]:
            level = int(value * (len(levels) - 1))
            graph += levels[level]
        
        return graph

    def format_bytes(self, bytes_value):
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f}{unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f}PB"

class NetPulseEliteCLI:
    def __init__(self):
        self.analyzer = RealTimeNetworkAnalyzer()
        
    def create_parser(self):
        parser = argparse.ArgumentParser(
            description='NetPulse Elite - Real-time Network Analysis Platform',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python netpulse_elite.py                    # Dashboard mode
  python netpulse_elite.py -m interfaces     # Interface monitoring
  python netpulse_elite.py -m traffic        # Traffic analysis
  python netpulse_elite.py -m topology       # Network topology
  python netpulse_elite.py -m quality        # Quality monitoring
  python netpulse_elite.py -i eth0           # Specific interface
  python netpulse_elite.py --json            # JSON output mode
            """
        )
        
        parser.add_argument('-m', '--mode', 
                          choices=['dashboard', 'interfaces', 'traffic', 'topology', 'quality'],
                          default='dashboard',
                          help='Display mode (default: dashboard)')
        
        parser.add_argument('-i', '--interface',
                          help='Network interface to monitor')
        
        parser.add_argument('-u', '--update-interval', type=float, default=1.0,
                          help='Update interval in seconds (default: 1.0)')
        
        parser.add_argument('--json', action='store_true',
                          help='Output in JSON format')
        
        parser.add_argument('--no-color', action='store_true',
                          help='Disable colored output')
        
        parser.add_argument('-v', '--verbose', action='store_true',
                          help='Verbose output')
        
        return parser
    
    async def run(self, args):
        """Run the network analyzer"""
        
        if args.no_color:
            # Disable colors
            for attr in dir(Colors):
                if not attr.startswith('_'):
                    setattr(Colors, attr, '')
        
        self.analyzer.update_interval = args.update_interval
        
        if args.json:
            # JSON output mode - collect data and output once
            await self.run_json_mode(args)
        else:
            # Interactive real-time mode
            await self.analyzer.start_analysis(
                interface=args.interface,
                display_mode=args.mode
            )
    
    async def run_json_mode(self, args):
        """Run in JSON output mode"""
        print("Collecting network data...", file=sys.stderr)
        
        # Run analysis for a short period to collect data
        analysis_task = asyncio.create_task(
            self.analyzer.start_analysis(args.interface, args.mode)
        )
        
        # Wait for some data to be collected
        await asyncio.sleep(10)
        
        # Stop analysis
        self.analyzer.running = False
        
        # Collect and output data
        data = {
            'timestamp': datetime.now().isoformat(),
            'interfaces': {name: {
                'status': iface.status,
                'ip_addresses': iface.ip_addresses,
                'mac_address': iface.mac_address,
                'rx_bytes': iface.rx_bytes,
                'tx_bytes': iface.tx_bytes,
                'rx_packets': iface.rx_packets,
                'tx_packets': iface.tx_packets,
                'speed': iface.speed,
                'mtu': iface.mtu
            } for name, iface in self.analyzer.interfaces.items()},
            'topology': {
                'gateway': self.analyzer.topology.gateway if self.analyzer.topology else None,
                'local_networks': self.analyzer.topology.local_networks if self.analyzer.topology else [],
                'dns_servers': self.analyzer.topology.dns_servers if self.analyzer.topology else [],
                'discovered_devices': len(self.analyzer.topology.discovered_devices) if self.analyzer.topology else 0
            },
            'quality': {target: {
                'latency_avg': q.latency_avg,
                'packet_loss': q.packet_loss,
                'jitter': q.jitter,
                'dns_resolution_time': q.dns_resolution_time
            } for target, q in self.analyzer.network_quality.items()},
            'traffic_stats': dict(self.analyzer.packet_capture_stats)
        }
        
        print(json.dumps(data, indent=2))

def display_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██║     ███████╗█████╗  
██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝███████╗███████║███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝

{Colors.PURPLE}███████╗██╗     ██╗████████╗███████╗{Colors.RESET}
{Colors.PURPLE}██╔════╝██║     ██║╚══██╔══╝██╔════╝{Colors.RESET}  
{Colors.PURPLE}█████╗  ██║     ██║   ██║   █████╗  {Colors.RESET}
{Colors.PURPLE}██╔══╝  ██║     ██║   ██║   ██╔══╝  {Colors.RESET}
{Colors.PURPLE}███████╗███████╗██║   ██║   ███████╗{Colors.RESET}
{Colors.PURPLE}╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝{Colors.RESET}

{Colors.BOLD}Real-time Network Analysis Platform{Colors.RESET}
{Colors.CYAN}• Live Network Interface Monitoring{Colors.RESET}
{Colors.CYAN}• Real-time Traffic Analysis & Protocol Distribution{Colors.RESET}
{Colors.CYAN}• Network Topology Discovery & Device Detection{Colors.RESET}
{Colors.CYAN}• Network Quality Monitoring (Latency, Jitter, Loss){Colors.RESET}
{Colors.CYAN}• Bandwidth Utilization & Performance Metrics{Colors.RESET}
{Colors.CYAN}• Interactive Real-time Dashboard{Colors.RESET}

{Colors.GREEN}Version 2.0 Elite - Real-time Network Intelligence{Colors.RESET}
{Colors.BLUE}Focus: Performance | Topology | Quality | Real-time Analysis{Colors.RESET}
"""
    print(banner)

def check_dependencies():
    """Check for required dependencies"""
    required = ['psutil', 'netifaces', 'scapy', 'numpy', 'requests']
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"{Colors.RED}Missing dependencies: {', '.join(missing)}{Colors.RESET}")
        print(f"{Colors.YELLOW}Install with: pip install {' '.join(missing)}{Colors.RESET}")
        return False
    
    return True

def check_permissions():
    """Check if running with sufficient permissions for packet capture"""
    if platform.system() != "Windows" and os.geteuid() != 0:
        print(f"{Colors.YELLOW}Warning: Not running as root. Some features may be limited.{Colors.RESET}")
        print(f"{Colors.YELLOW}For full functionality, run as: sudo python3 {sys.argv[0]}{Colors.RESET}")

async def main():
    # Handle graceful shutdown
    def signal_handler(signum, frame):
        print(f"\n{Colors.YELLOW}Shutting down NetPulse Elite...{Colors.RESET}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    display_banner()
    
    if not check_dependencies():
        sys.exit(1)
    
    check_permissions()
    
    cli = NetPulseEliteCLI()
    parser = cli.create_parser()
    args = parser.parse_args()
    
    try:
        await cli.run(args)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Analysis stopped by user{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}NetPulse Elite terminated{Colors.RESET}")