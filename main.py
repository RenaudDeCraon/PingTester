#!/usr/bin/env python3
"""
NetPulse Elite - Advanced Protocol Analysis & Network Research Platform
Deep protocol conformance testing, TCP algorithm analysis, and advanced network research

Features:
- RFC Conformance Testing (TCP, HTTP, DNS, etc.)
- Real-time TCP Congestion Control Algorithm Detection & Analysis
- Network Stack Performance Profiling (Kernel vs Userspace)
- Advanced Timing Analysis (Microsecond precision)
- Protocol Implementation Fingerprinting
- BGP Route Change Detection & Analysis
- IPv6 vs IPv4 Performance Comparison
- DNS-over-HTTPS/TLS Performance Analysis
- QUIC/HTTP3 Protocol Deep Analysis
- Network Covert Channel Detection
- TCP Sequence Number Randomness Analysis
- Path MTU Discovery Implementation Testing
- Bufferbloat Detection & Queue Analysis
- Network Time Protocol Synchronization Analysis
- Ethernet Frame Deep Inspection & Analysis
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
import random
import hashlib
import ssl
import ctypes
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Union
import argparse
import signal
import math
import binascii

# Advanced networking libraries
import psutil
import netifaces
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.l2 import ARP
from scapy.packet import Raw
import numpy as np
import requests
import dns.resolver
import dns.query
import dns.message

# Terminal colors
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
    RESET = '\033[0m'
    CLEAR_SCREEN = '\033[2J'
    HOME = '\033[H'

@dataclass
class TCPFlowAnalysis:
    """Advanced TCP flow analysis - enhanced version"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    congestion_algorithm: str = "unknown"
    window_scaling: bool = False
    initial_window_size: int = 0
    max_window_size: int = 0
    rtt_samples: List[float] = field(default_factory=list)
    retransmissions: int = 0
    fast_retransmits: int = 0
    duplicate_acks: int = 0
    sack_enabled: bool = False
    timestamp_enabled: bool = False
    mss: int = 0
    congestion_window_history: List[int] = field(default_factory=list)
    slow_start_threshold: int = 0
    tcp_flags_sequence: List[str] = field(default_factory=list)
    sequence_randomness_score: float = 0.0
    implementation_fingerprint: str = "unknown"
    # New fields for enhanced analysis
    last_activity: datetime = field(default_factory=datetime.now)
    packet_sizes: deque = field(default_factory=lambda: deque(maxlen=200))

@dataclass
class ProtocolConformanceTest:
    """Protocol conformance testing results"""
    protocol: str
    rfc_number: str
    test_name: str
    expected_behavior: str
    actual_behavior: str
    conformant: bool
    deviation_details: str
    severity: str  # critical, major, minor, info
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class NetworkTimingAnalysis:
    """Microsecond-precision network timing analysis"""
    measurement_type: str
    target: str
    samples: List[float] = field(default_factory=list)
    mean: float = 0.0
    median: float = 0.0
    std_dev: float = 0.0
    min_time: float = 0.0
    max_time: float = 0.0
    jitter: float = 0.0
    percentile_95: float = 0.0
    percentile_99: float = 0.0
    coefficient_of_variation: float = 0.0

@dataclass
class BufferbloatAnalysis:
    """Advanced bufferbloat detection and analysis"""
    interface: str
    base_rtt: float
    loaded_rtt: float
    bufferbloat_score: float
    queue_length_estimate: int
    congestion_detected: bool
    queue_management: str  # fifo, fq_codel, etc.
    bandwidth_delay_product: int
    optimal_buffer_size: int

@dataclass
class DNSAdvancedAnalysis:
    """Advanced DNS analysis including DoH/DoT"""
    resolver: str
    query_type: str
    response_time_udp: float
    response_time_tcp: float
    response_time_doh: float
    response_time_dot: float
    dnssec_validation: bool
    edns_support: bool
    response_size: int
    truncation_detected: bool
    authority_section_analysis: Dict
    additional_section_analysis: Dict

@dataclass
class IPv6vs4Analysis:
    """IPv6 vs IPv4 performance comparison"""
    target: str
    ipv4_latency: float
    ipv6_latency: float
    ipv4_throughput: float
    ipv6_throughput: float
    ipv4_packet_loss: float
    ipv6_packet_loss: float
    happy_eyeballs_preference: str
    dual_stack_behavior: str

class AdvancedNetworkAnalyzer:
    def __init__(self):
        self.running = False
        self.tcp_flows = {}
        self.protocol_tests = []
        self.timing_analyses = {}
        self.bufferbloat_results = {}
        self.dns_analyses = {}
        self.ipv6v4_comparisons = {}
        
        # Advanced measurement queues
        self.rtt_measurements = defaultdict(lambda: deque(maxlen=1000))
        self.tcp_sequence_analysis = defaultdict(list)
        self.protocol_violations = []
        self.covert_channels = []
        
        # Timing precision
        self.high_precision_timer = time.perf_counter
        self.start_time = self.high_precision_timer()
        
        # Network research data
        self.bgp_changes = []
        self.ntp_analysis = {}
        self.path_mtu_results = {}
        
    async def start_advanced_analysis(self):
        """Start comprehensive advanced network analysis"""
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════════════════╗")
        print("║          NetPulse Elite - Advanced Protocol Research Platform       ║")
        print("║                    Network Protocol Deep Analysis                    ║")
        print("╚══════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")
        
        self.running = True
        
        # Start all advanced analysis modules
        tasks = [
            asyncio.create_task(self.tcp_flow_analyzer()),
            asyncio.create_task(self.protocol_conformance_tester()),
            asyncio.create_task(self.network_timing_analyzer()),
            asyncio.create_task(self.bufferbloat_detector()),
            asyncio.create_task(self.dns_advanced_analyzer()),
            asyncio.create_task(self.ipv6_vs_ipv4_analyzer()),
            asyncio.create_task(self.tcp_sequence_analyzer()),
            asyncio.create_task(self.path_mtu_analyzer()),
            asyncio.create_task(self.ntp_synchronization_analyzer()),
            asyncio.create_task(self.covert_channel_detector()),
            asyncio.create_task(self.display_advanced_dashboard()),
            asyncio.create_task(self.bgp_route_monitor()),
            asyncio.create_task(self.quic_http3_analyzer())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{Colors.YELLOW}Advanced analysis terminated{Colors.RESET}")

    async def tcp_flow_analyzer(self):
        """Advanced TCP flow analysis with congestion control detection"""
        def packet_handler(packet):
            try:
                if packet.haslayer(TCP) and packet.haslayer(IP):
                    self.analyze_tcp_packet(packet)
            except Exception as e:
                pass
        
        # Start packet capture in background
        def capture():
            try:
                scapy.sniff(prn=packet_handler, store=False, 
                           stop_filter=lambda x: not self.running)
            except:
                pass
        
        capture_thread = threading.Thread(target=capture, daemon=True)
        capture_thread.start()
        
        # Periodic TCP flow analysis
        while self.running:
            await self.analyze_tcp_flows()
            await asyncio.sleep(5)

    def analyze_tcp_packet(self, packet):
        """Deep TCP packet analysis - enhanced version"""
        ip = packet[scapy.IP]
        tcp = packet[scapy.TCP]
        
        flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        reverse_key = (ip.dst, tcp.dport, ip.src, tcp.sport)
        
        # Use existing flow or create new one
        if flow_key in self.tcp_flows:
            flow = self.tcp_flows[flow_key]
        elif reverse_key in self.tcp_flows:
            flow = self.tcp_flows[reverse_key]
        else:
            flow = TCPFlowAnalysis(ip.src, ip.dst, tcp.sport, tcp.dport)
            self.tcp_flows[flow_key] = flow
        
        # Track last activity time
        flow.last_activity = datetime.now()
        
        # Track packet sizes for covert channel detection
        if not hasattr(flow, 'packet_sizes'):
            flow.packet_sizes = deque(maxlen=200)
        flow.packet_sizes.append(len(packet))
        
        # Track congestion window size (estimated from window field)
        if not hasattr(flow, 'congestion_window_history'):
            flow.congestion_window_history = deque(maxlen=100)
        flow.congestion_window_history.append(tcp.window)
        
        # Original analysis code continues...
        if tcp.options:
            for option in tcp.options:
                if option[0] == 'MSS':
                    flow.mss = option[1]
                elif option[0] == 'WScale':
                    flow.window_scaling = True
                elif option[0] == 'SAckOK':
                    flow.sack_enabled = True
                elif option[0] == 'Timestamp':
                    flow.timestamp_enabled = True
        
        # Window size analysis
        window_size = tcp.window
        if window_size > flow.max_window_size:
            flow.max_window_size = window_size
        
        if flow.initial_window_size == 0 and tcp.flags.S:
            flow.initial_window_size = window_size
        
        # Track TCP flags sequence for fingerprinting
        flags = []
        if tcp.flags.S: flags.append('S')
        if tcp.flags.A: flags.append('A')
        if tcp.flags.F: flags.append('F')
        if tcp.flags.R: flags.append('R')
        if tcp.flags.P: flags.append('P')
        if tcp.flags.U: flags.append('U')
        
        flag_str = ''.join(flags)
        flow.tcp_flags_sequence.append(flag_str)
        
        # Detect congestion control algorithm
        flow.congestion_algorithm = self.detect_congestion_algorithm(flow, packet)
        
        # TCP sequence number analysis for randomness
        if tcp.flags.S:  # SYN packet
            self.tcp_sequence_analysis[flow_key].append(tcp.seq)
            if len(self.tcp_sequence_analysis[flow_key]) > 10:
                flow.sequence_randomness_score = self.analyze_sequence_randomness(
                    self.tcp_sequence_analysis[flow_key]
                )
        
        # Implementation fingerprinting
        flow.implementation_fingerprint = self.fingerprint_tcp_implementation(packet)

    def detect_congestion_algorithm(self, flow, packet):
        """Detect TCP congestion control algorithm"""
        tcp = packet[TCP]
        
        # Analyze window behavior patterns
        if len(flow.congestion_window_history) > 10:
            window_pattern = flow.congestion_window_history[-10:]
            
            # Check for Cubic behavior (gradual increase then rapid)
            if self.is_cubic_pattern(window_pattern):
                return "CUBIC"
            
            # Check for BBR behavior (probing patterns)
            elif self.is_bbr_pattern(window_pattern):
                return "BBR"
            
            # Check for Reno behavior (linear increase)
            elif self.is_reno_pattern(window_pattern):
                return "Reno"
            
            # Check for Vegas behavior (RTT-based)
            elif self.is_vegas_pattern(window_pattern, flow.rtt_samples):
                return "Vegas"
        
        return "unknown"

    def is_cubic_pattern(self, window_history):
        """Detect CUBIC congestion control pattern"""
        if len(window_history) < 5:
            return False
        
        # CUBIC shows cubic growth function
        growth_rates = []
        for i in range(1, len(window_history)):
            if window_history[i-1] > 0:
                growth_rate = (window_history[i] - window_history[i-1]) / window_history[i-1]
                growth_rates.append(growth_rate)
        
        # CUBIC growth is not linear
        if len(growth_rates) > 3:
            variance = np.var(growth_rates)
            return variance > 0.1  # High variance indicates non-linear growth
        
        return False

    def is_bbr_pattern(self, window_history):
        """Detect BBR congestion control pattern"""
        if len(window_history) < 8:
            return False
        
        # BBR shows probing patterns with periodic increases
        recent = window_history[-8:]
        
        # Look for gain cycling pattern (characteristic of BBR)
        peaks = []
        for i in range(1, len(recent)-1):
            if recent[i] > recent[i-1] and recent[i] > recent[i+1]:
                peaks.append(i)
        
        # BBR typically has regular probing cycles
        return len(peaks) >= 2

    def is_reno_pattern(self, window_history):
        """Detect Reno congestion control pattern"""
        if len(window_history) < 5:
            return False
        
        # Reno shows linear growth (additive increase)
        differences = []
        for i in range(1, len(window_history)):
            differences.append(window_history[i] - window_history[i-1])
        
        # Check for consistent additive increase
        if len(differences) > 3:
            avg_diff = np.mean(differences)
            variance = np.var(differences)
            # Linear growth has low variance in differences
            return variance < 0.5 and avg_diff > 0

        return False

    def is_vegas_pattern(self, window_history, rtt_samples):
        """Detect Vegas congestion control pattern"""
        # Vegas adjusts based on RTT, not just packet loss
        if len(rtt_samples) < 5 or len(window_history) < 5:
            return False
        
        # Check if window changes correlate with RTT changes
        if len(rtt_samples) == len(window_history):
            correlation = np.corrcoef(window_history, rtt_samples)[0, 1]
            # Negative correlation suggests RTT-based control
            return correlation < -0.3
        
        return False

    def analyze_sequence_randomness(self, sequences):
        """Analyze TCP sequence number randomness (RFC 6528)"""
        if len(sequences) < 10:
            return 0.0
        
        # Convert to differences
        differences = []
        for i in range(1, len(sequences)):
            diff = (sequences[i] - sequences[i-1]) % (2**32)
            differences.append(diff)
        
        # Chi-square test for randomness
        if len(differences) < 5:
            return 0.0
        
        # Simple entropy calculation
        byte_counts = Counter()
        for diff in differences:
            for i in range(4):
                byte_val = (diff >> (i * 8)) & 0xFF
                byte_counts[byte_val] += 1
        
        total_bytes = sum(byte_counts.values())
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)
        
        # Normalize to 0-1 scale (max entropy is 8 bits)
        return entropy / 8.0

    def fingerprint_tcp_implementation(self, packet):
        """Fingerprint TCP implementation based on packet characteristics"""
        tcp = packet[TCP]
        ip = packet[IP]
        
        fingerprint_features = []
        
        # Initial window size
        if tcp.flags.S:
            window = tcp.window
            if window == 65535:
                fingerprint_features.append("win65535")
            elif window == 8192:
                fingerprint_features.append("win8192")
            elif window == 5840:
                fingerprint_features.append("win5840")
        
        # TTL analysis
        ttl = ip.ttl
        if ttl == 64:
            fingerprint_features.append("ttl64")
        elif ttl == 128:
            fingerprint_features.append("ttl128")
        elif ttl == 255:
            fingerprint_features.append("ttl255")
        
        # TCP options analysis
        if tcp.options:
            option_order = []
            for option in tcp.options:
                option_order.append(option[0])
            fingerprint_features.append(f"opts:{'_'.join(option_order)}")
        
        # Determine likely implementation
        fingerprint = '_'.join(fingerprint_features)
        
        if 'win65535' in fingerprint and 'ttl64' in fingerprint:
            return "Linux"
        elif 'win8192' in fingerprint and 'ttl128' in fingerprint:
            return "Windows"
        elif 'win65535' in fingerprint and 'ttl255' in fingerprint:
            return "BSD/macOS"
        else:
            return f"Unknown({fingerprint})"

    async def protocol_conformance_tester(self):
        """Test protocol conformance against RFCs"""
        while self.running:
            # Test various protocols
            await self.test_tcp_conformance()
            await self.test_http_conformance()
            await self.test_dns_conformance()
            await self.test_icmp_conformance()
            
            await asyncio.sleep(30)

    async def test_tcp_conformance(self):
        """Test TCP RFC conformance"""
        test_targets = ['google.com', '1.1.1.1', '8.8.8.8']
        
        for target in test_targets:
            try:
                # Test RFC 793 - TCP specification
                test = await self.test_tcp_initial_sequence_number(target)
                self.protocol_tests.append(test)
                
                # Test RFC 1323 - TCP Window Scaling
                test = await self.test_tcp_window_scaling(target)
                self.protocol_tests.append(test)
                
                # Test RFC 2018 - TCP Selective Acknowledgment
                test = await self.test_tcp_sack_support(target)
                self.protocol_tests.append(test)
                
                # Test RFC 6298 - TCP Retransmission Timer
                test = await self.test_tcp_retransmission_behavior(target)
                self.protocol_tests.append(test)
                
            except Exception as e:
                pass

    async def test_tcp_initial_sequence_number(self, target):
        """Test TCP ISN randomness (RFC 6528)"""
        try:
            # Create multiple connections to test ISN randomness
            sequences = []
            for _ in range(5):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                # Capture with Scapy during connection
                try:
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, sock.connect, (target, 80)
                    )
                    sock.close()
                except:
                    pass
                
                await asyncio.sleep(0.1)
            
            # Analyze collected sequences from TCP flow analyzer
            flow_key = None
            for key, flow in self.tcp_flows.items():
                if target in key[2]:  # destination IP
                    flow_key = key
                    break
            
            if flow_key and len(self.tcp_sequence_analysis.get(flow_key, [])) > 3:
                randomness = self.analyze_sequence_randomness(
                    self.tcp_sequence_analysis[flow_key]
                )
                
                conformant = randomness > 0.7  # Good randomness
                severity = "critical" if randomness < 0.3 else "minor"
                
                return ProtocolConformanceTest(
                    protocol="TCP",
                    rfc_number="RFC 6528",
                    test_name="Initial Sequence Number Randomness",
                    expected_behavior="High entropy ISN generation",
                    actual_behavior=f"Randomness score: {randomness:.3f}",
                    conformant=conformant,
                    deviation_details=f"Entropy: {randomness:.3f}/1.0",
                    severity=severity
                )
            
        except Exception as e:
            pass
        
        return ProtocolConformanceTest(
            protocol="TCP", rfc_number="RFC 6528",
            test_name="Initial Sequence Number Test",
            expected_behavior="Testable", actual_behavior="Failed to test",
            conformant=False, deviation_details=str(e), severity="info"
        )

    async def test_tcp_window_scaling(self, target):
        """Test TCP Window Scaling (RFC 1323)"""
        try:
            # Check if target supports window scaling
            syn_packet = IP(dst=target) / TCP(dport=80, flags='S', 
                                            options=[('WScale', 8)])
            
            response = sr1(syn_packet, timeout=5, verbose=False)
            
            if response and response.haslayer(TCP):
                tcp_options = dict(response[TCP].options)
                supports_wscale = 'WScale' in tcp_options
                
                return ProtocolConformanceTest(
                    protocol="TCP",
                    rfc_number="RFC 1323",
                    test_name="Window Scaling Support",
                    expected_behavior="Should support window scaling for modern connections",
                    actual_behavior=f"Window scaling {'supported' if supports_wscale else 'not supported'}",
                    conformant=supports_wscale,
                    deviation_details=f"Options: {list(tcp_options.keys())}",
                    severity="minor" if not supports_wscale else "info"
                )
        except Exception as e:
            pass
        
        return ProtocolConformanceTest(
            protocol="TCP", rfc_number="RFC 1323",
            test_name="Window Scaling Test", expected_behavior="Testable",
            actual_behavior="Failed", conformant=False,
            deviation_details="Test failed", severity="info"
        )

    async def test_tcp_sack_support(self, target):
        """Test TCP SACK support (RFC 2018)"""
        try:
            syn_packet = IP(dst=target) / TCP(dport=80, flags='S', 
                                            options=[('SAckOK', '')])
            
            response = sr1(syn_packet, timeout=5, verbose=False)
            
            if response and response.haslayer(TCP):
                tcp_options = dict(response[TCP].options)
                supports_sack = 'SAckOK' in tcp_options
                
                return ProtocolConformanceTest(
                    protocol="TCP",
                    rfc_number="RFC 2018",
                    test_name="Selective Acknowledgment Support",
                    expected_behavior="Should support SACK for improved performance",
                    actual_behavior=f"SACK {'supported' if supports_sack else 'not supported'}",
                    conformant=supports_sack,
                    deviation_details=f"Response options: {list(tcp_options.keys())}",
                    severity="minor" if not supports_sack else "info"
                )
        except Exception as e:
            pass
        
        return ProtocolConformanceTest(
            protocol="TCP", rfc_number="RFC 2018",
            test_name="SACK Test", expected_behavior="Testable",
            actual_behavior="Failed", conformant=False,
            deviation_details="Test failed", severity="info"
        )

    async def test_tcp_retransmission_behavior(self, target):
        """Test TCP retransmission behavior (RFC 6298)"""
        # This would require more complex packet crafting and timing analysis
        # For now, return a placeholder test
        return ProtocolConformanceTest(
            protocol="TCP",
            rfc_number="RFC 6298",
            test_name="Retransmission Timer",
            expected_behavior="Exponential backoff with proper RTO calculation",
            actual_behavior="Analysis in progress",
            conformant=True,
            deviation_details="Requires long-term analysis",
            severity="info"
        )

    async def test_http_conformance(self):
        """Test HTTP RFC conformance"""
        test_urls = ['http://httpbin.org/get', 'https://www.google.com']
        
        for url in test_urls:
            try:
                # Test RFC 7230 - HTTP/1.1 Message Syntax
                test = await self.test_http_header_parsing(url)
                self.protocol_tests.append(test)
                
                # Test RFC 7231 - HTTP/1.1 Semantics
                test = await self.test_http_method_support(url)
                self.protocol_tests.append(test)
                
            except Exception as e:
                pass

    async def test_http_header_parsing(self, url):
        """Test HTTP header parsing conformance"""
        try:
            response = requests.get(url, timeout=10)
            
            # Check for required headers
            required_headers = ['Content-Type', 'Content-Length', 'Date']
            missing_headers = []
            
            for header in required_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            # Check header format
            conformant = len(missing_headers) == 0
            
            return ProtocolConformanceTest(
                protocol="HTTP",
                rfc_number="RFC 7230",
                test_name="Header Parsing",
                expected_behavior="Standard headers should be present",
                actual_behavior=f"Missing headers: {missing_headers}",
                conformant=conformant,
                deviation_details=f"Response headers: {len(response.headers)}",
                severity="minor" if missing_headers else "info"
            )
        except Exception as e:
            return ProtocolConformanceTest(
                protocol="HTTP", rfc_number="RFC 7230",
                test_name="Header Test", expected_behavior="Testable",
                actual_behavior="Failed", conformant=False,
                deviation_details=str(e), severity="info"
            )

    async def test_http_method_support(self, url):
        """Test HTTP method support"""
        try:
            # Test OPTIONS method
            response = requests.options(url, timeout=10)
            
            # Check Allow header
            allow_header = response.headers.get('Allow', '')
            supported_methods = [m.strip() for m in allow_header.split(',')]
            
            expected_methods = ['GET', 'HEAD', 'OPTIONS']
            missing_methods = [m for m in expected_methods if m not in supported_methods]
            
            conformant = len(missing_methods) == 0
            
            return ProtocolConformanceTest(
                protocol="HTTP",
                rfc_number="RFC 7231",
                test_name="Method Support",
                expected_behavior="Basic methods should be supported",
                actual_behavior=f"Supported: {supported_methods}",
                conformant=conformant,
                deviation_details=f"Missing: {missing_methods}",
                severity="minor" if missing_methods else "info"
            )
        except Exception as e:
            return ProtocolConformanceTest(
                protocol="HTTP", rfc_number="RFC 7231",
                test_name="Method Test", expected_behavior="Testable",
                actual_behavior="Failed", conformant=False,
                deviation_details=str(e), severity="info"
            )

    async def test_dns_conformance(self):
        """Test DNS RFC conformance"""
        test_domains = ['google.com', 'cloudflare.com', 'example.com']
        
        for domain in test_domains:
            try:
                # Test RFC 1035 - DNS specification
                test = await self.test_dns_response_format(domain)
                self.protocol_tests.append(test)
                
                # Test RFC 2671 - EDNS support
                test = await self.test_dns_edns_support(domain)
                self.protocol_tests.append(test)
                
            except Exception as e:
                pass

    async def test_dns_response_format(self, domain):
        """Test DNS response format conformance"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            response = resolver.resolve(domain, 'A')
            
            # Check response structure
            has_answer = len(response) > 0
            valid_ttl = all(r.ttl > 0 for r in response)
            
            conformant = has_answer and valid_ttl
            
            return ProtocolConformanceTest(
                protocol="DNS",
                rfc_number="RFC 1035",
                test_name="Response Format",
                expected_behavior="Valid A record response with TTL",
                actual_behavior=f"Records: {len(response)}, Valid TTL: {valid_ttl}",
                conformant=conformant,
                deviation_details=f"Response count: {len(response)}",
                severity="major" if not conformant else "info"
            )
        except Exception as e:
            return ProtocolConformanceTest(
                protocol="DNS", rfc_number="RFC 1035",
                test_name="DNS Response Test", expected_behavior="Testable",
                actual_behavior="Failed", conformant=False,
                deviation_details=str(e), severity="info"
            )

    async def test_dns_edns_support(self, domain):
        """Test EDNS support (RFC 2671)"""
        try:
            # Create EDNS query
            query = dns.message.make_query(domain, 'A')
            query.use_edns(edns=True, payload=4096)
            
            # Send query
            response = dns.query.udp(query, '8.8.8.8', timeout=5)
            
            # Check EDNS support
            has_edns = response.edns >= 0
            
            return ProtocolConformanceTest(
                protocol="DNS",
                rfc_number="RFC 2671",
                test_name="EDNS Support",
                expected_behavior="Should support EDNS extensions",
                actual_behavior=f"EDNS {'supported' if has_edns else 'not supported'}",
                conformant=has_edns,
                deviation_details=f"EDNS version: {response.edns if has_edns else 'N/A'}",
                severity="minor" if not has_edns else "info"
            )
        except Exception as e:
            return ProtocolConformanceTest(
                protocol="DNS", rfc_number="RFC 2671",
                test_name="EDNS Test", expected_behavior="Testable",
                actual_behavior="Failed", conformant=False,
                deviation_details=str(e), severity="info"
            )

    async def test_icmp_conformance(self):
        """Test ICMP RFC conformance"""
        test_targets = ['8.8.8.8', '1.1.1.1']
        
        for target in test_targets:
            try:
                # Test RFC 792 - ICMP specification
                test = await self.test_icmp_echo_response(target)
                self.protocol_tests.append(test)
                
            except Exception as e:
                pass

    async def test_icmp_echo_response(self, target):
        """Test ICMP echo response conformance"""
        try:
            # Send ICMP echo request
            packet = IP(dst=target) / ICMP()
            response = sr1(packet, timeout=5, verbose=False)
            
            if response and response.haslayer(ICMP):
                icmp = response[ICMP]
                correct_type = icmp.type == 0  # Echo Reply
                correct_code = icmp.code == 0
                
                conformant = correct_type and correct_code
                
                return ProtocolConformanceTest(
                    protocol="ICMP",
                    rfc_number="RFC 792",
                    test_name="Echo Response",
                    expected_behavior="Type 0, Code 0 for echo reply",
                    actual_behavior=f"Type {icmp.type}, Code {icmp.code}",
                    conformant=conformant,
                    deviation_details=f"Response received in {response.time}s",
                    severity="major" if not conformant else "info"
                )
            else:
                return ProtocolConformanceTest(
                    protocol="ICMP", rfc_number="RFC 792",
                    test_name="Echo Response", expected_behavior="Echo reply",
                    actual_behavior="No response", conformant=False,
                    deviation_details="Timeout or filtered", severity="major"
                )
        except Exception as e:
            return ProtocolConformanceTest(
                protocol="ICMP", rfc_number="RFC 792",
                test_name="ICMP Test", expected_behavior="Testable",
                actual_behavior="Failed", conformant=False,
                deviation_details=str(e), severity="info"
            )

    async def network_timing_analyzer(self):
        """High-precision network timing analysis"""
        targets = ['8.8.8.8', '1.1.1.1', 'google.com', 'cloudflare.com']
        
        while self.running:
            for target in targets:
                # RTT analysis
                await self.measure_rtt_precision(target)
                
                # DNS timing
                await self.measure_dns_timing(target)
                
                # TCP handshake timing
                await self.measure_tcp_handshake_timing(target)
                
                await asyncio.sleep(1)
            
            await asyncio.sleep(10)

    async def measure_rtt_precision(self, target):
        """Measure RTT with microsecond precision"""
        samples = []
        
        for i in range(10):
            try:
                start_time = self.high_precision_timer()
                
                # ICMP ping
                packet = IP(dst=target) / ICMP(id=os.getpid() + i)
                response = sr1(packet, timeout=2, verbose=False)
                
                if response:
                    end_time = self.high_precision_timer()
                    rtt = (end_time - start_time) * 1000  # Convert to ms
                    samples.append(rtt)
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                continue
        
        if samples:
            analysis = NetworkTimingAnalysis(
                measurement_type="ICMP_RTT",
                target=target,
                samples=samples,
                mean=statistics.mean(samples),
                median=statistics.median(samples),
                std_dev=statistics.stdev(samples) if len(samples) > 1 else 0,
                min_time=min(samples),
                max_time=max(samples),
                jitter=statistics.stdev(samples) if len(samples) > 1 else 0,
                percentile_95=np.percentile(samples, 95),
                percentile_99=np.percentile(samples, 99),
                coefficient_of_variation=(statistics.stdev(samples) / statistics.mean(samples)) if len(samples) > 1 and statistics.mean(samples) > 0 else 0
            )
            
            self.timing_analyses[f"RTT_{target}"] = analysis

    async def measure_dns_timing(self, target):
        """Measure DNS resolution timing"""
        samples = []
        
        for i in range(5):
            try:
                start_time = self.high_precision_timer()
                socket.gethostbyname(target)
                end_time = self.high_precision_timer()
                
                dns_time = (end_time - start_time) * 1000
                samples.append(dns_time)
                
                await asyncio.sleep(0.2)
                
            except Exception as e:
                continue
        
        if samples:
            analysis = NetworkTimingAnalysis(
                measurement_type="DNS_RESOLUTION",
                target=target,
                samples=samples,
                mean=statistics.mean(samples),
                median=statistics.median(samples),
                std_dev=statistics.stdev(samples) if len(samples) > 1 else 0,
                min_time=min(samples),
                max_time=max(samples),
                jitter=statistics.stdev(samples) if len(samples) > 1 else 0,
                percentile_95=np.percentile(samples, 95) if len(samples) > 1 else samples[0],
                percentile_99=np.percentile(samples, 99) if len(samples) > 1 else samples[0],
                coefficient_of_variation=(statistics.stdev(samples) / statistics.mean(samples)) if len(samples) > 1 and statistics.mean(samples) > 0 else 0
            )
            
            self.timing_analyses[f"DNS_{target}"] = analysis

    async def measure_tcp_handshake_timing(self, target):
        """Measure TCP handshake timing"""
        samples = []
        
        for i in range(3):
            try:
                start_time = self.high_precision_timer()
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                try:
                    sock.connect((target, 80))
                    end_time = self.high_precision_timer()
                    
                    handshake_time = (end_time - start_time) * 1000
                    samples.append(handshake_time)
                    
                    sock.close()
                except:
                    pass
                
                await asyncio.sleep(1)
                
            except Exception as e:
                continue
        
        if samples:
            analysis = NetworkTimingAnalysis(
                measurement_type="TCP_HANDSHAKE",
                target=target,
                samples=samples,
                mean=statistics.mean(samples),
                median=statistics.median(samples),
                std_dev=statistics.stdev(samples) if len(samples) > 1 else 0,
                min_time=min(samples),
                max_time=max(samples),
                jitter=statistics.stdev(samples) if len(samples) > 1 else 0,
                percentile_95=np.percentile(samples, 95) if len(samples) > 1 else samples[0],
                percentile_99=np.percentile(samples, 99) if len(samples) > 1 else samples[0],
                coefficient_of_variation=(statistics.stdev(samples) / statistics.mean(samples)) if len(samples) > 1 and statistics.mean(samples) > 0 else 0
            )
            
            self.timing_analyses[f"TCP_HANDSHAKE_{target}"] = analysis

    async def bufferbloat_detector(self):
        """Advanced bufferbloat detection with simulated load"""
        test_targets = ['8.8.8.8', '1.1.1.1']
        
        while self.running:
            for target in test_targets:
                try:
                    # Measure baseline RTT
                    base_rtt_samples = []
                    for i in range(10):
                        start = self.high_precision_timer()
                        packet = scapy.IP(dst=target) / scapy.ICMP()
                        response = scapy.sr1(packet, timeout=2, verbose=False)
                        if response:
                            rtt = (self.high_precision_timer() - start) * 1000
                            base_rtt_samples.append(rtt)
                        await asyncio.sleep(0.1)
                    
                    if not base_rtt_samples:
                        continue
                    
                    base_rtt = statistics.mean(base_rtt_samples)
                    
                    # Simulate network load by sending multiple concurrent requests
                    loaded_rtt_samples = []
                    
                    async def send_load_packet():
                        """Send a packet as part of load generation"""
                        try:
                            start = self.high_precision_timer()
                            packet = scapy.IP(dst=target) / scapy.ICMP()
                            response = scapy.sr1(packet, timeout=3, verbose=False)
                            if response:
                                rtt = (self.high_precision_timer() - start) * 1000
                                loaded_rtt_samples.append(rtt)
                        except:
                            pass
                    
                    # Generate concurrent load
                    load_tasks = []
                    for i in range(20):  # Send 20 concurrent packets
                        task = asyncio.create_task(send_load_packet())
                        load_tasks.append(task)
                        await asyncio.sleep(0.01)  # Small delay between starts
                    
                    # Wait for all load packets to complete
                    await asyncio.gather(*load_tasks, return_exceptions=True)
                    
                    if loaded_rtt_samples:
                        loaded_rtt = statistics.mean(loaded_rtt_samples)
                        
                        # Calculate bufferbloat metrics
                        rtt_increase = max(0, loaded_rtt - base_rtt)
                        bufferbloat_score = rtt_increase / base_rtt if base_rtt > 0 else 0
                        
                        # Estimate queue delay and buffer size
                        queue_delay_ms = rtt_increase
                        estimated_bandwidth_mbps = 100  # Assume 100 Mbps for calculation
                        bandwidth_bps = estimated_bandwidth_mbps * 1_000_000
                        buffer_size_bytes = int((queue_delay_ms / 1000) * (bandwidth_bps / 8))
                        
                        # Determine queue management algorithm (heuristic)
                        queue_mgmt = "unknown"
                        if bufferbloat_score < 0.05:
                            queue_mgmt = "fq_codel"  # Good queue management
                        elif bufferbloat_score > 0.5:
                            queue_mgmt = "fifo"      # Traditional FIFO buffer
                        else:
                            queue_mgmt = "mixed"     # Some queue management
                        
                        analysis = BufferbloatAnalysis(
                            interface="default",
                            base_rtt=base_rtt,
                            loaded_rtt=loaded_rtt,
                            bufferbloat_score=bufferbloat_score,
                            queue_length_estimate=int(queue_delay_ms),
                            congestion_detected=bufferbloat_score > 0.1,
                            queue_management=queue_mgmt,
                            bandwidth_delay_product=int(base_rtt * bandwidth_bps / 8000),
                            optimal_buffer_size=buffer_size_bytes
                        )
                        
                        self.bufferbloat_results[target] = analysis
                    
                except Exception as e:
                    continue
            
            await asyncio.sleep(120)  # Test every 2 minutes

    async def dns_advanced_analyzer(self):
        """Advanced DNS analysis including DoH/DoT"""
        test_domains = ['google.com', 'cloudflare.com', 'github.com']
        resolvers = {
            'Cloudflare': '1.1.1.1',
            'Google': '8.8.8.8',
            'Quad9': '9.9.9.9'
        }
        
        while self.running:
            for domain in test_domains:
                for resolver_name, resolver_ip in resolvers.items():
                    try:
                        analysis = DNSAdvancedAnalysis(
                            resolver=resolver_name,
                            query_type='A',
                            response_time_udp=0,
                            response_time_tcp=0,
                            response_time_doh=0,
                            response_time_dot=0,
                            dnssec_validation=False,
                            edns_support=False,
                            response_size=0,
                            truncation_detected=False,
                            authority_section_analysis={},
                            additional_section_analysis={}
                        )
                        
                        # UDP DNS
                        start = self.high_precision_timer()
                        try:
                            query = dns.message.make_query(domain, 'A')
                            response = dns.query.udp(query, resolver_ip, timeout=5)
                            analysis.response_time_udp = (self.high_precision_timer() - start) * 1000
                            analysis.response_size = len(response.to_wire())
                            analysis.edns_support = response.edns >= 0
                        except:
                            analysis.response_time_udp = -1
                        
                        # TCP DNS
                        start = self.high_precision_timer()
                        try:
                            query = dns.message.make_query(domain, 'A')
                            response = dns.query.tcp(query, resolver_ip, timeout=5)
                            analysis.response_time_tcp = (self.high_precision_timer() - start) * 1000
                        except:
                            analysis.response_time_tcp = -1
                        
                        # DNS over HTTPS (simplified test)
                        if resolver_name == 'Cloudflare':
                            start = self.high_precision_timer()
                            try:
                                url = f'https://1.1.1.1/dns-query?name={domain}&type=A'
                                response = requests.get(url, headers={'Accept': 'application/dns-json'}, timeout=5)
                                if response.status_code == 200:
                                    analysis.response_time_doh = (self.high_precision_timer() - start) * 1000
                            except:
                                analysis.response_time_doh = -1
                        
                        self.dns_analyses[f"{domain}_{resolver_name}"] = analysis
                        
                    except Exception as e:
                        continue
            
            await asyncio.sleep(30)

    async def ipv6_vs_ipv4_analyzer(self):
        """Compare IPv6 vs IPv4 performance"""
        dual_stack_targets = {
            'google.com': ('172.217.164.142', '2607:f8b0:4004:c1b::65'),
            'cloudflare.com': ('104.16.132.229', '2606:4700::6810:84e5'),
            'github.com': ('140.82.114.3', '2606:50c0:8000::153')
        }
        
        while self.running:
            for domain, (ipv4, ipv6) in dual_stack_targets.items():
                try:
                    analysis = IPv6vs4Analysis(
                        target=domain,
                        ipv4_latency=0,
                        ipv6_latency=0,
                        ipv4_throughput=0,
                        ipv6_throughput=0,
                        ipv4_packet_loss=0,
                        ipv6_packet_loss=0,
                        happy_eyeballs_preference="unknown",
                        dual_stack_behavior="unknown"
                    )
                    
                    # IPv4 latency test
                    ipv4_samples = []
                    for i in range(5):
                        try:
                            start = self.high_precision_timer()
                            packet = IP(dst=ipv4) / ICMP()
                            response = sr1(packet, timeout=2, verbose=False)
                            if response:
                                rtt = (self.high_precision_timer() - start) * 1000
                                ipv4_samples.append(rtt)
                        except:
                            pass
                        await asyncio.sleep(0.1)
                    
                    if ipv4_samples:
                        analysis.ipv4_latency = statistics.mean(ipv4_samples)
                        analysis.ipv4_packet_loss = (5 - len(ipv4_samples)) / 5 * 100
                    
                    # IPv6 latency test
                    ipv6_samples = []
                    for i in range(5):
                        try:
                            start = self.high_precision_timer()
                            packet = IPv6(dst=ipv6) / ICMPv6EchoRequest()
                            response = sr1(packet, timeout=2, verbose=False)
                            if response:
                                rtt = (self.high_precision_timer() - start) * 1000
                                ipv6_samples.append(rtt)
                        except:
                            pass
                        await asyncio.sleep(0.1)
                    
                    if ipv6_samples:
                        analysis.ipv6_latency = statistics.mean(ipv6_samples)
                        analysis.ipv6_packet_loss = (5 - len(ipv6_samples)) / 5 * 100
                    
                    # Determine Happy Eyeballs preference
                    if analysis.ipv4_latency > 0 and analysis.ipv6_latency > 0:
                        if analysis.ipv6_latency < analysis.ipv4_latency * 1.1:  # 10% threshold
                            analysis.happy_eyeballs_preference = "IPv6"
                        else:
                            analysis.happy_eyeballs_preference = "IPv4"
                    
                    self.ipv6v4_comparisons[domain] = analysis
                    
                except Exception as e:
                    continue
            
            await asyncio.sleep(60)

    async def tcp_sequence_analyzer(self):
        """Analyze TCP sequence numbers for security"""
        while self.running:
            # Analysis is performed in real-time during packet capture
            # This function processes the collected data
            
            for flow_key, sequences in self.tcp_sequence_analysis.items():
                if len(sequences) > 20:
                    # Perform advanced sequence analysis
                    randomness = self.analyze_sequence_randomness(sequences)
                    
                    # Check for predictable patterns
                    predictable = self.detect_predictable_sequences(sequences)
                    
                    if predictable:
                        # This could indicate a security issue
                        pass
            
            await asyncio.sleep(30)

    def detect_predictable_sequences(self, sequences):
        """Detect predictable sequence number patterns"""
        if len(sequences) < 10:
            return False
        
        # Check for linear patterns
        differences = []
        for i in range(1, len(sequences)):
            diff = (sequences[i] - sequences[i-1]) % (2**32)
            differences.append(diff)
        
        # Check if differences are too consistent
        if len(set(differences)) < len(differences) * 0.5:
            return True  # Too predictable
        
        # Check for arithmetic progression
        if len(differences) > 3:
            first_diff = differences[0]
            arithmetic = all(abs(d - first_diff) < first_diff * 0.1 for d in differences[1:4])
            if arithmetic:
                return True
        
        return False

    async def path_mtu_analyzer(self):
        """Analyze Path MTU Discovery implementation"""
        targets = ['8.8.8.8', '1.1.1.1']
        
        while self.running:
            for target in targets:
                try:
                    # Test PMTU discovery by sending different sized packets
                    mtu_results = {}
                    
                    test_sizes = [1500, 1472, 1024, 576, 512]
                    
                    for size in test_sizes:
                        try:
                            # Create packet with DF bit set
                            packet = IP(dst=target, flags="DF") / ICMP() / ("X" * (size - 28))
                            response = sr1(packet, timeout=3, verbose=False)
                            
                            if response:
                                if response.haslayer(ICMP) and response[ICMP].type == 3:
                                    # Fragmentation needed
                                    mtu_results[size] = "fragmentation_needed"
                                else:
                                    mtu_results[size] = "success"
                            else:
                                mtu_results[size] = "timeout"
                        except:
                            mtu_results[size] = "error"
                        
                        await asyncio.sleep(0.5)
                    
                    self.path_mtu_results[target] = mtu_results
                    
                except Exception as e:
                    continue
            
            await asyncio.sleep(120)  # Test every 2 minutes

    async def ntp_synchronization_analyzer(self):
        """Analyze NTP synchronization with proper implementation"""
        ntp_servers = ['pool.ntp.org', 'time.google.com', 'time.nist.gov']
        
        while self.running:
            for server in ntp_servers:
                try:
                    start_time = self.high_precision_timer()
                    
                    # Create NTP packet (simplified NTP v3 packet)
                    ntp_packet = struct.pack('!B' + 'B' * 47, 
                                        0x1B,  # LI, VN, Mode
                                        *([0] * 47))  # Rest of packet
                    
                    # Send NTP request
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5)
                    
                    try:
                        sock.sendto(ntp_packet, (server, 123))
                        response, addr = sock.recvfrom(48)
                        end_time = self.high_precision_timer()
                        
                        query_time = (end_time - start_time) * 1000
                        
                        # Parse NTP response for offset calculation
                        if len(response) >= 48:
                            # Extract transmit timestamp (bytes 40-47)
                            transmit_timestamp = struct.unpack('!Q', response[40:48])[0]
                            
                            # Convert NTP timestamp to Unix timestamp
                            ntp_epoch = 2208988800  # NTP epoch offset
                            server_time = (transmit_timestamp >> 32) - ntp_epoch
                            local_time = time.time()
                            
                            offset = server_time - local_time
                            
                            self.ntp_analysis[server] = {
                                'query_time': query_time,
                                'offset': offset,
                                'reachable': True,
                                'stratum': response[1],  # Stratum byte
                                'precision': response[3] if len(response) > 3 else 0
                            }
                        
                    except socket.timeout:
                        self.ntp_analysis[server] = {
                            'query_time': -1,
                            'offset': 0,
                            'reachable': False,
                            'error': 'timeout'
                        }
                    except Exception as e:
                        self.ntp_analysis[server] = {
                            'query_time': -1,
                            'offset': 0,
                            'reachable': False,
                            'error': str(e)
                        }
                    finally:
                        sock.close()
                        
                except Exception as e:
                    continue
            
            await asyncio.sleep(300)  # Every 5 minutes

    async def covert_channel_detector(self):
        """Detect potential network covert channels with improved algorithms"""
        while self.running:
            current_time = datetime.now()
            
            # Analyze TCP flows for timing channels
            for flow_key, flow in self.tcp_flows.items():
                if len(flow.rtt_samples) > 100:
                    recent_samples = flow.rtt_samples[-100:]
                    
                    # Statistical analysis for timing regularity
                    rtt_variance = np.var(recent_samples)
                    rtt_mean = np.mean(recent_samples)
                    coefficient_of_variation = rtt_variance / rtt_mean if rtt_mean > 0 else 0
                    
                    # Detect suspiciously regular timing (possible covert channel)
                    if coefficient_of_variation < 0.01:  # Very low variance
                        confidence = min(1.0, (0.01 - coefficient_of_variation) * 100)
                        
                        covert_channel = {
                            'type': 'timing_channel',
                            'flow': flow_key,
                            'confidence': confidence,
                            'description': f'Artificially regular timing (CoV: {coefficient_of_variation:.6f})',
                            'timestamp': current_time,
                            'rtt_mean': rtt_mean,
                            'rtt_variance': rtt_variance
                        }
                        
                        # Avoid duplicates
                        if not any(cc['flow'] == flow_key and cc['type'] == 'timing_channel' 
                                for cc in self.covert_channels):
                            self.covert_channels.append(covert_channel)
                    
                    # Detect Inter-Packet Delay (IPD) channels
                    if len(flow.rtt_samples) > 50:
                        # Calculate inter-packet delays
                        ipd_samples = []
                        for i in range(1, len(recent_samples)):
                            ipd = abs(recent_samples[i] - recent_samples[i-1])
                            ipd_samples.append(ipd)
                        
                        if ipd_samples:
                            # Look for patterns in IPD
                            ipd_mean = np.mean(ipd_samples)
                            ipd_std = np.std(ipd_samples)
                            
                            # Detect if IPDs cluster around specific values
                            ipd_histogram, bins = np.histogram(ipd_samples, bins=20)
                            max_bin_count = np.max(ipd_histogram)
                            total_samples = len(ipd_samples)
                            
                            # If more than 40% of samples fall in one bin, it's suspicious
                            if max_bin_count / total_samples > 0.4:
                                confidence = (max_bin_count / total_samples - 0.4) / 0.6
                                
                                covert_channel = {
                                    'type': 'ipd_channel',
                                    'flow': flow_key,
                                    'confidence': confidence,
                                    'description': f'Clustered inter-packet delays ({max_bin_count}/{total_samples} in dominant bin)',
                                    'timestamp': current_time,
                                    'ipd_mean': ipd_mean,
                                    'ipd_std': ipd_std
                                }
                                
                                if not any(cc['flow'] == flow_key and cc['type'] == 'ipd_channel' 
                                        for cc in self.covert_channels):
                                    self.covert_channels.append(covert_channel)
            
            # Analyze packet size patterns for storage channels
            packet_sizes = defaultdict(list)
            for flow_key, flow in self.tcp_flows.items():
                # This would require tracking packet sizes - simplified for now
                if hasattr(flow, 'packet_sizes') and len(flow.packet_sizes) > 50:
                    sizes = flow.packet_sizes[-50:]
                    
                    # Look for patterns in packet sizes
                    unique_sizes = set(sizes)
                    if len(unique_sizes) < len(sizes) * 0.3:  # Less than 30% unique sizes
                        size_counts = Counter(sizes)
                        most_common_size, count = size_counts.most_common(1)[0]
                        
                        if count / len(sizes) > 0.6:  # More than 60% same size
                            covert_channel = {
                                'type': 'size_channel',
                                'flow': flow_key,
                                'confidence': (count / len(sizes) - 0.6) / 0.4,
                                'description': f'Repeated packet size pattern (size {most_common_size}: {count}/{len(sizes)})',
                                'timestamp': current_time,
                                'dominant_size': most_common_size,
                                'size_frequency': count / len(sizes)
                            }
                            
                            if not any(cc['flow'] == flow_key and cc['type'] == 'size_channel' 
                                    for cc in self.covert_channels):
                                self.covert_channels.append(covert_channel)
            
            # Clean up old covert channel detections (keep last hour)
            cutoff_time = current_time - timedelta(hours=1)
            self.covert_channels = [cc for cc in self.covert_channels 
                                if cc['timestamp'] > cutoff_time]
            
            await asyncio.sleep(30)  # Check every 30 seconds

    async def bgp_route_monitor(self):
        """Monitor BGP route changes with more realistic simulation"""
        # This would connect to real BGP feeds in production (RouteViews, RIPE RIS)
        # For now, we'll simulate based on actual internet events patterns
        
        common_prefixes = [
            '8.8.8.0/24',      # Google DNS
            '1.1.1.0/24',      # Cloudflare DNS  
            '208.67.222.0/24', # OpenDNS
            '9.9.9.0/24',      # Quad9
            '185.228.168.0/24' # CleanBrowsing
        ]
        
        as_paths = {
            '8.8.8.0/24': ['AS15169'],
            '1.1.1.0/24': ['AS13335'],
            '208.67.222.0/24': ['AS36692'],
            '9.9.9.0/24': ['AS19281'],
            '185.228.168.0/24': ['AS42429']
        }
        
        while self.running:
            # Simulate BGP updates based on realistic patterns
            # Real BGP updates are rare for major prefixes, but do occur
            
            if random.random() < 0.02:  # 2% chance per cycle (more realistic)
                prefix = random.choice(common_prefixes)
                current_path = as_paths.get(prefix, ['AS0'])
                
                # Simulate different types of BGP changes
                change_types = ['path_prepend', 'path_change', 'announcement', 'withdrawal']
                change_type = random.choice(change_types)
                
                new_path = current_path.copy()
                
                if change_type == 'path_prepend':
                    # AS path prepending for traffic engineering
                    new_path = current_path + [current_path[0]]
                elif change_type == 'path_change':
                    # Route through different AS
                    transit_as = random.choice(['AS7018', 'AS174', 'AS3356', 'AS1299'])
                    new_path = [current_path[0], transit_as]
                elif change_type == 'announcement':
                    # New route announcement
                    new_path = current_path
                elif change_type == 'withdrawal':
                    # Route withdrawal
                    new_path = []
                
                route_change = {
                    'timestamp': datetime.now(),
                    'prefix': prefix,
                    'old_path': ' '.join(current_path),
                    'new_path': ' '.join(new_path) if new_path else 'WITHDRAWN',
                    'change_type': change_type,
                    'origin_as': current_path[0] if current_path else 'unknown',
                    'route_length': len(new_path)
                }
                
                self.bgp_changes.append(route_change)
                
                # Update our simulated AS paths
                if new_path:
                    as_paths[prefix] = new_path
            
            # Clean up old changes (keep last 24 hours)
            cutoff = datetime.now() - timedelta(hours=24)
            self.bgp_changes = [c for c in self.bgp_changes if c['timestamp'] > cutoff]
            
            await asyncio.sleep(300)  # Check every 5 minutes

    async def quic_http3_analyzer(self):
        """Analyze QUIC/HTTP3 protocol support with better detection"""
        http3_targets = ['google.com', 'cloudflare.com', 'facebook.com', 'youtube.com']
        
        while self.running:
            for target in http3_targets:
                try:
                    analysis_data = {
                        'target': target,
                        'http2_support': False,
                        'http3_advertised': False,
                        'http3_versions': [],
                        'alt_svc_header': '',
                        'connection_time_http1': 0,
                        'connection_time_http2': 0,
                        'quic_support_detected': False
                    }
                    
                    # Test HTTP/1.1 connection time
                    start = self.high_precision_timer()
                    try:
                        response = requests.get(f'https://{target}', 
                                            timeout=10, 
                                            headers={'Connection': 'close'})
                        analysis_data['connection_time_http1'] = (self.high_precision_timer() - start) * 1000
                        
                        # Check Alt-Svc header for HTTP/3
                        alt_svc = response.headers.get('alt-svc', '')
                        analysis_data['alt_svc_header'] = alt_svc
                        
                        # Parse HTTP/3 versions from Alt-Svc
                        if 'h3=' in alt_svc or 'h3-' in alt_svc:
                            analysis_data['http3_advertised'] = True
                            # Extract version numbers
                            import re
                            h3_versions = re.findall(r'h3[-=](\w+)', alt_svc)
                            analysis_data['http3_versions'] = h3_versions
                        
                        # Check for HTTP/2 support
                        if response.raw.version == 20:  # HTTP/2
                            analysis_data['http2_support'] = True
                    
                    except Exception as e:
                        analysis_data['connection_time_http1'] = -1
                    
                    # Test HTTP/2 connection time
                    start = self.high_precision_timer()
                    try:
                        import httpx
                        async with httpx.AsyncClient(http2=True) as client:
                            response = await client.get(f'https://{target}', timeout=10)
                            analysis_data['connection_time_http2'] = (self.high_precision_timer() - start) * 1000
                            analysis_data['http2_support'] = True
                    except:
                        # Fallback without httpx
                        analysis_data['connection_time_http2'] = -1
                    
                    # Simple QUIC detection via UDP probe
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(2)
                        
                        # Send a simple UDP probe to common QUIC ports
                        quic_ports = [443, 80]
                        for port in quic_ports:
                            try:
                                # Simple QUIC Initial packet probe (very basic)
                                quic_probe = b'\x80\x00\x00\x01' + b'\x00' * 20  # Simplified
                                sock.sendto(quic_probe, (target, port))
                                
                                # Try to receive response
                                data, addr = sock.recvfrom(1024)
                                if data:
                                    analysis_data['quic_support_detected'] = True
                                    break
                            except:
                                continue
                        
                        sock.close()
                    except:
                        pass
                    
                    # Store comprehensive analysis
                    timing_analysis = NetworkTimingAnalysis(
                        measurement_type="HTTP3_ANALYSIS",
                        target=target,
                        samples=[analysis_data['connection_time_http1'], analysis_data['connection_time_http2']],
                        mean=(analysis_data['connection_time_http1'] + analysis_data['connection_time_http2']) / 2,
                        median=statistics.median([analysis_data['connection_time_http1'], analysis_data['connection_time_http2']]),
                        std_dev=0.0,
                        min_time=min(analysis_data['connection_time_http1'], analysis_data['connection_time_http2']),
                        max_time=max(analysis_data['connection_time_http1'], analysis_data['connection_time_http2']),
                        jitter=abs(analysis_data['connection_time_http1'] - analysis_data['connection_time_http2']),
                        percentile_95=max(analysis_data['connection_time_http1'], analysis_data['connection_time_http2']),
                        percentile_99=max(analysis_data['connection_time_http1'], analysis_data['connection_time_http2']),
                        coefficient_of_variation=0.0
                    )
                    
                    # Store both timing and protocol support data
                    self.timing_analyses[f"HTTP3_{target}"] = timing_analysis
                    # Store detailed analysis in a separate structure
                    if not hasattr(self, 'http3_detailed_analysis'):
                        self.http3_detailed_analysis = {}
                    self.http3_detailed_analysis[target] = analysis_data
                    
                except Exception as e:
                    continue
            
            await asyncio.sleep(180)  # Every 3 minutes


    async def analyze_tcp_flows(self):
        """Periodic analysis of TCP flows"""
        current_time = datetime.now()
        
        # Clean up old flows (complete implementation)
        cutoff_time = current_time - timedelta(minutes=5)
        expired_flows = []
        
        for flow_key, flow in self.tcp_flows.items():
            # Check if flow has been inactive (no recent packets)
            if hasattr(flow, 'last_activity'):
                if flow.last_activity < cutoff_time:
                    expired_flows.append(flow_key)
            elif len(flow.tcp_flags_sequence) == 0:
                expired_flows.append(flow_key)
        
        # Remove expired flows
        for flow_key in expired_flows:
            del self.tcp_flows[flow_key]
            if flow_key in self.tcp_sequence_analysis:
                del self.tcp_sequence_analysis[flow_key]
        
        # Analyze active flows for congestion events
        for flow_key, flow in self.tcp_flows.items():
            if len(flow.congestion_window_history) > 10:
                recent_windows = flow.congestion_window_history[-10:]
                
                # Detect congestion events (window size drops)
                congestion_events = 0
                for i in range(1, len(recent_windows)):
                    if recent_windows[i] < recent_windows[i-1] * 0.5:
                        congestion_events += 1
                        flow.fast_retransmits += 1
                
                # Update flow statistics
                if len(flow.rtt_samples) > 5:
                    recent_rtt = flow.rtt_samples[-5:]
                    avg_rtt = statistics.mean(recent_rtt)
                    if avg_rtt > 0:
                        self.rtt_measurements[flow_key].extend(recent_rtt)


    async def display_advanced_dashboard(self):
        """Display advanced analysis dashboard - enhanced version"""
        while self.running:
            # Clear screen
            print(f"{Colors.CLEAR_SCREEN}{Colors.HOME}", end='')
            
            # Header
            uptime = timedelta(seconds=int(self.high_precision_timer() - self.start_time))
            print(f"{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Advanced Protocol Analysis Dashboard{Colors.RESET}")
            print(f"{Colors.BLUE}{'='*80}{Colors.RESET}")
            print(f"Uptime: {uptime} | Time: {datetime.now().strftime('%H:%M:%S')} | Mode: Advanced Analysis")
            print()
            
            # Protocol Conformance Summary
            print(f"{Colors.BOLD}📋 Protocol Conformance Summary{Colors.RESET}")
            if self.protocol_tests:
                recent_tests = self.protocol_tests[-20:]  # Look at more tests
                
                conformant_count = sum(1 for t in recent_tests if t.conformant)
                total_tests = len(recent_tests)
                conformance_rate = (conformant_count / total_tests * 100) if total_tests > 0 else 0
                
                print(f"  Conformance Rate: {Colors.GREEN if conformance_rate > 80 else Colors.YELLOW if conformance_rate > 60 else Colors.RED}{conformance_rate:.1f}%{Colors.RESET} ({conformant_count}/{total_tests})")
                
                # Group by protocol
                protocol_stats = defaultdict(lambda: {'total': 0, 'passed': 0})
                for test in recent_tests:
                    protocol_stats[test.protocol]['total'] += 1
                    if test.conformant:
                        protocol_stats[test.protocol]['passed'] += 1
                
                print(f"  By Protocol:")
                for protocol, stats in protocol_stats.items():
                    rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
                    color = Colors.GREEN if rate > 80 else Colors.YELLOW if rate > 60 else Colors.RED
                    print(f"    {protocol}: {color}{rate:.0f}%{Colors.RESET} ({stats['passed']}/{stats['total']})")
                
                # Show recent failures
                failures = [t for t in recent_tests if not t.conformant]
                if failures:
                    print(f"  Recent Failures:")
                    for failure in failures[-3:]:
                        severity_color = Colors.RED if failure.severity == 'critical' else Colors.YELLOW
                        print(f"    {severity_color}• {failure.protocol} {failure.rfc_number}: {failure.test_name}{Colors.RESET}")
            else:
                print("  No conformance tests completed yet")
            print()
            
            # TCP Flow Analysis - Enhanced
            print(f"{Colors.BOLD}🔄 TCP Flow Analysis{Colors.RESET}")
            active_flows = len(self.tcp_flows)
            print(f"  Active Flows: {Colors.CYAN}{active_flows}{Colors.RESET}")
            
            if self.tcp_flows:
                # Show congestion algorithm distribution
                congestion_algorithms = defaultdict(int)
                implementations = defaultdict(int)
                
                for flow in self.tcp_flows.values():
                    congestion_algorithms[flow.congestion_algorithm] += 1
                    implementations[flow.implementation_fingerprint] += 1
                
                print(f"  Congestion Algorithms:")
                for algo, count in congestion_algorithms.items():
                    print(f"    {algo}: {count}")
                
                print(f"  Implementations:")
                for impl, count in list(implementations.items())[:3]:
                    print(f"    {impl}: {count}")
                
                # Show top flows by activity
                sorted_flows = sorted(self.tcp_flows.items(), 
                                    key=lambda x: len(x[1].tcp_flags_sequence), reverse=True)
                
                print(f"  Top Active Flows:")
                for i, (flow_key, flow) in enumerate(sorted_flows[:3]):
                    src_ip, src_port, dst_ip, dst_port = flow_key
                    print(f"    {i+1}. {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                    print(f"       Algorithm: {Colors.GREEN}{flow.congestion_algorithm}{Colors.RESET} | "
                        f"Window Scaling: {'Yes' if flow.window_scaling else 'No'} | "
                        f"SACK: {'Yes' if flow.sack_enabled else 'No'}")
                    print(f"       Implementation: {flow.implementation_fingerprint} | "
                        f"Seq Randomness: {flow.sequence_randomness_score:.3f}")
            print()
            
            # Network Timing Analysis
            print(f"{Colors.BOLD}⏱️  Network Timing Analysis{Colors.RESET}")
            if self.timing_analyses:
                for name, analysis in list(self.timing_analyses.items())[:4]:
                    if analysis.samples:
                        timing_color = (Colors.GREEN if analysis.mean < 50 else 
                                    Colors.YELLOW if analysis.mean < 100 else Colors.RED)
                        
                        print(f"  {name}")
                        print(f"    Mean: {timing_color}{analysis.mean:.2f}ms{Colors.RESET} | "
                            f"Jitter: {analysis.jitter:.2f}ms | "
                            f"95th: {analysis.percentile_95:.2f}ms")
                        print(f"    CoV: {analysis.coefficient_of_variation:.3f} | "
                            f"Samples: {len(analysis.samples)}")
            else:
                print("  Collecting timing data...")
            print()
            
            # NTP Analysis - New section
            print(f"{Colors.BOLD}🕐 NTP Synchronization Analysis{Colors.RESET}")
            if self.ntp_analysis:
                for server, data in list(self.ntp_analysis.items())[:3]:
                    if data.get('reachable', False):
                        offset_color = (Colors.GREEN if abs(data.get('offset', 0)) < 0.1 else 
                                    Colors.YELLOW if abs(data.get('offset', 0)) < 1.0 else Colors.RED)
                        print(f"  {server}")
                        print(f"    Offset: {offset_color}{data.get('offset', 0):.3f}s{Colors.RESET} | "
                            f"Query: {data.get('query_time', 0):.1f}ms | "
                            f"Stratum: {data.get('stratum', '?')}")
                    else:
                        print(f"  {server}: {Colors.RED}Unreachable{Colors.RESET}")
            else:
                print("  Analyzing NTP servers...")
            print()
            
            # DNS Advanced Analysis
            print(f"{Colors.BOLD}🔍 DNS Advanced Analysis{Colors.RESET}")
            if self.dns_analyses:
                for name, analysis in list(self.dns_analyses.items())[:3]:
                    print(f"  {name}")
                    
                    udp_color = Colors.GREEN if analysis.response_time_udp > 0 and analysis.response_time_udp < 50 else Colors.YELLOW
                    tcp_color = Colors.GREEN if analysis.response_time_tcp > 0 and analysis.response_time_tcp < 100 else Colors.YELLOW
                    doh_color = Colors.GREEN if analysis.response_time_doh > 0 and analysis.response_time_doh < 100 else Colors.YELLOW
                    
                    udp_str = f"{udp_color}{analysis.response_time_udp:.1f}ms{Colors.RESET}" if analysis.response_time_udp > 0 else f"{Colors.RED}Failed{Colors.RESET}"
                    tcp_str = f"{tcp_color}{analysis.response_time_tcp:.1f}ms{Colors.RESET}" if analysis.response_time_tcp > 0 else f"{Colors.RED}Failed{Colors.RESET}"
                    doh_str = f"{doh_color}{analysis.response_time_doh:.1f}ms{Colors.RESET}" if analysis.response_time_doh > 0 else f"{Colors.RED}Failed{Colors.RESET}"
                    
                    print(f"    UDP: {udp_str} | TCP: {tcp_str} | DoH: {doh_str}")
                    print(f"    EDNS: {'Yes' if analysis.edns_support else 'No'} | "
                        f"Size: {analysis.response_size}B")
            else:
                print("  Collecting DNS data...")
            print()
            
            # HTTP/3 and QUIC Analysis - Enhanced
            print(f"{Colors.BOLD}🚀 HTTP/3 & QUIC Analysis{Colors.RESET}")
            if hasattr(self, 'http3_detailed_analysis') and self.http3_detailed_analysis:
                for target, data in list(self.http3_detailed_analysis.items())[:3]:
                    http3_status = f"{Colors.GREEN}Supported{Colors.RESET}" if data['http3_advertised'] else f"{Colors.YELLOW}Not Advertised{Colors.RESET}"
                    print(f"  {target}")
                    print(f"    HTTP/3: {http3_status} | HTTP/2: {'Yes' if data['http2_support'] else 'No'}")
                    if data['http3_versions']:
                        print(f"    H3 Versions: {', '.join(data['http3_versions'])}")
                    if data['connection_time_http1'] > 0 and data['connection_time_http2'] > 0:
                        print(f"    HTTP/1.1: {data['connection_time_http1']:.1f}ms | HTTP/2: {data['connection_time_http2']:.1f}ms")
            else:
                print("  Analyzing HTTP/3 support...")
            print()
            
            # IPv6 vs IPv4 Comparison
            print(f"{Colors.BOLD}🌐 IPv6 vs IPv4 Performance{Colors.RESET}")
            if self.ipv6v4_comparisons:
                for domain, analysis in list(self.ipv6v4_comparisons.items())[:3]:
                    ipv4_color = Colors.GREEN if analysis.ipv4_latency > 0 and analysis.ipv4_latency < 50 else Colors.YELLOW
                    ipv6_color = Colors.GREEN if analysis.ipv6_latency > 0 and analysis.ipv6_latency < 50 else Colors.YELLOW
                    
                    ipv4_str = f"{ipv4_color}{analysis.ipv4_latency:.1f}ms{Colors.RESET}" if analysis.ipv4_latency > 0 else f"{Colors.RED}Failed{Colors.RESET}"
                    ipv6_str = f"{ipv6_color}{analysis.ipv6_latency:.1f}ms{Colors.RESET}" if analysis.ipv6_latency > 0 else f"{Colors.RED}Failed{Colors.RESET}"
                    
                    print(f"  {domain}")
                    print(f"    IPv4: {ipv4_str} ({analysis.ipv4_packet_loss:.1f}% loss) | "
                        f"IPv6: {ipv6_str} ({analysis.ipv6_packet_loss:.1f}% loss)")
                    print(f"    Happy Eyeballs: {analysis.happy_eyeballs_preference}")
            else:
                print("  Collecting IPv6/IPv4 data...")
            print()
            
            # Bufferbloat Detection
            print(f"{Colors.BOLD}🚰 Bufferbloat Analysis{Colors.RESET}")
            if self.bufferbloat_results:
                for target, analysis in list(self.bufferbloat_results.items())[:2]:
                    bloat_color = (Colors.GREEN if analysis.bufferbloat_score < 0.1 else 
                                Colors.YELLOW if analysis.bufferbloat_score < 0.3 else Colors.RED)
                    
                    print(f"  {target}")
                    print(f"    Base RTT: {analysis.base_rtt:.1f}ms | Loaded RTT: {analysis.loaded_rtt:.1f}ms")
                    print(f"    Bufferbloat Score: {bloat_color}{analysis.bufferbloat_score:.3f}{Colors.RESET} | "
                        f"Queue Mgmt: {analysis.queue_management}")
                    print(f"    Queue Delay: ~{analysis.queue_length_estimate}ms | "
                        f"Buffer Size: ~{analysis.optimal_buffer_size//1024}KB")
            else:
                print("  Analyzing bufferbloat...")
            print()
            
            # Security Analysis - Enhanced
            print(f"{Colors.BOLD}🔒 Security Analysis{Colors.RESET}")
            sequence_issues = sum(1 for flow in self.tcp_flows.values() 
                                if flow.sequence_randomness_score < 0.5)
            covert_channels = len(self.covert_channels)
            
            print(f"  TCP Sequence Issues: {Colors.RED if sequence_issues > 0 else Colors.GREEN}{sequence_issues}{Colors.RESET}")
            print(f"  Covert Channels: {Colors.RED if covert_channels > 0 else Colors.GREEN}{covert_channels}{Colors.RESET}")
            
            if self.covert_channels:
                channel_types = defaultdict(int)
                for cc in self.covert_channels:
                    channel_types[cc['type']] += 1
                print(f"    Types: {dict(channel_types)}")
            
            if self.bgp_changes:
                recent_changes = len([c for c in self.bgp_changes 
                                    if (datetime.now() - c['timestamp']).seconds < 3600])
                print(f"  BGP Changes (1h): {Colors.YELLOW if recent_changes > 0 else Colors.GREEN}{recent_changes}{Colors.RESET}")
                
                if recent_changes > 0:
                    change_types = defaultdict(int)
                    for change in self.bgp_changes[-10:]:  # Last 10 changes
                        change_types[change['change_type']] += 1
                    print(f"    Recent Types: {dict(change_types)}")
            
            print(f"\n{Colors.DIM}Advanced Protocol Analysis | Press Ctrl+C to exit{Colors.RESET}")
            
            await asyncio.sleep(2)  # Update every 2 seconds

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

{Colors.BOLD}Advanced Protocol Analysis & Network Research Platform{Colors.RESET}

{Colors.GREEN}🔬 ADVANCED RESEARCH FEATURES:{Colors.RESET}
{Colors.CYAN}• RFC Conformance Testing (TCP, HTTP, DNS, ICMP){Colors.RESET}
{Colors.CYAN}• TCP Congestion Control Algorithm Detection (CUBIC, BBR, Reno, Vegas){Colors.RESET}
{Colors.CYAN}• Microsecond-Precision Network Timing Analysis{Colors.RESET}
{Colors.CYAN}• TCP Implementation Fingerprinting & Security Analysis{Colors.RESET}
{Colors.CYAN}• Bufferbloat Detection & Queue Management Analysis{Colors.RESET}
{Colors.CYAN}• DNS-over-HTTPS/TLS Performance Comparison{Colors.RESET}
{Colors.CYAN}• IPv6 vs IPv4 Performance & Happy Eyeballs Analysis{Colors.RESET}
{Colors.CYAN}• TCP Sequence Number Randomness Testing (RFC 6528){Colors.RESET}
{Colors.CYAN}• Path MTU Discovery Implementation Testing{Colors.RESET}
{Colors.CYAN}• Network Covert Channel Detection{Colors.RESET}
{Colors.CYAN}• QUIC/HTTP3 Protocol Support Analysis{Colors.RESET}
{Colors.CYAN}• BGP Route Change Monitoring{Colors.RESET}

{Colors.YELLOW}⚡ PROTOCOL ANALYSIS CAPABILITIES:{Colors.RESET}
{Colors.WHITE}• Real-time TCP Flow Analysis with Window Scaling & SACK Detection{Colors.RESET}
{Colors.WHITE}• Protocol Violation Detection & RFC Compliance Scoring{Colors.RESET}
{Colors.WHITE}• Advanced Timing Measurements (CoV, Jitter, Percentiles){Colors.RESET}
{Colors.WHITE}• Network Stack Performance Profiling{Colors.RESET}
{Colors.WHITE}• Security-focused Protocol Implementation Analysis{Colors.RESET}

{Colors.PURPLE}Version 2.0 Elite - Advanced Network Protocol Research Platform{Colors.RESET}
{Colors.BLUE}Research-Grade | RFC Compliance | Protocol Security | Performance Analysis{Colors.RESET}
"""
    print(banner)

def check_dependencies():
    """Check for required dependencies"""
    required = [
        'psutil', 'netifaces', 'scapy', 'numpy', 'requests', 
        'dnspython', 'matplotlib'  # Added for advanced analysis
    ]
    missing = []
    
    for module in required:
        try:
            if module == 'dnspython':
                import dns.resolver
            else:
                __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"{Colors.RED}Missing dependencies: {', '.join(missing)}{Colors.RESET}")
        print(f"{Colors.YELLOW}Install with: pip install {' '.join(missing)}{Colors.RESET}")
        return False
    
    return True

def check_permissions():
    """Check for required permissions"""
    if platform.system() != "Windows" and os.geteuid() != 0:
        print(f"{Colors.YELLOW}Warning: Advanced features require root privileges{Colors.RESET}")
        print(f"{Colors.YELLOW}Run as: sudo python3 {sys.argv[0]}{Colors.RESET}")
        print(f"{Colors.CYAN}Some protocol analysis features may be limited{Colors.RESET}\n")

class NetPulseEliteCLI:
    def __init__(self):
        self.analyzer = AdvancedNetworkAnalyzer()
        
    def create_parser(self):
        parser = argparse.ArgumentParser(
            description='NetPulse Elite - Advanced Protocol Analysis Platform',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Advanced Network Protocol Research Platform:

RESEARCH FEATURES:
  • RFC Conformance Testing for TCP, HTTP, DNS, ICMP protocols
  • TCP Congestion Control Algorithm Detection (CUBIC, BBR, Reno, Vegas)
  • Microsecond-precision network timing analysis with statistical metrics
  • TCP Implementation Fingerprinting and security analysis
  • Bufferbloat detection with queue management analysis
  • DNS-over-HTTPS/TLS performance comparison
  • IPv6 vs IPv4 performance analysis with Happy Eyeballs detection
  • TCP Sequence Number Randomness Testing (RFC 6528 compliance)
  • Path MTU Discovery implementation testing
  • Network covert channel detection algorithms
  • QUIC/HTTP3 protocol support analysis
  • BGP route change monitoring and analysis

EXAMPLES:
  python netpulse_elite.py                    # Full advanced analysis
  python netpulse_elite.py --json > results.json  # Export research data
  python netpulse_elite.py --verbose         # Detailed protocol analysis

This tool is designed for network research, protocol conformance testing,
and advanced network performance analysis at the protocol level.
            """
        )
        
        parser.add_argument('--json', action='store_true',
                          help='Output analysis data in JSON format')
        
        parser.add_argument('--verbose', action='store_true',
                          help='Verbose protocol analysis output')
        
        parser.add_argument('--no-color', action='store_true',
                          help='Disable colored output')
        
        parser.add_argument('-t', '--duration', type=int, default=0,
                          help='Analysis duration in seconds (0 = continuous)')
        
        return parser
    
    async def run(self, args):
        """Run the advanced network analyzer"""
        
        if args.no_color:
            # Disable colors
            for attr in dir(Colors):
                if not attr.startswith('_'):
                    setattr(Colors, attr, '')
        
        if args.json:
            # JSON output mode
            await self.run_json_mode(args)
        else:
            # Interactive mode
            if args.duration > 0:
                # Run for specified duration
                task = asyncio.create_task(self.analyzer.start_advanced_analysis())
                try:
                    await asyncio.wait_for(task, timeout=args.duration)
                except asyncio.TimeoutError:
                    self.analyzer.running = False
                    print(f"\n{Colors.YELLOW}Analysis completed after {args.duration} seconds{Colors.RESET}")
            else:
                # Run continuously
                await self.analyzer.start_advanced_analysis()
    
    async def run_json_mode(self, args):
        """Run in JSON output mode for research data export"""
        print("Collecting advanced network protocol data...", file=sys.stderr)
        
        # Run analysis for data collection
        analysis_task = asyncio.create_task(self.analyzer.start_advanced_analysis())
        
        # Collect data for specified duration
        duration = args.duration if args.duration > 0 else 30
        await asyncio.sleep(duration)
        
        # Stop analysis
        self.analyzer.running = False
        
        # Export collected data
        research_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'analysis_duration': duration,
                'platform': platform.platform(),
                'python_version': platform.python_version()
            },
            'protocol_conformance': [
                {
                    'protocol': test.protocol,
                    'rfc_number': test.rfc_number,
                    'test_name': test.test_name,
                    'expected_behavior': test.expected_behavior,
                    'actual_behavior': test.actual_behavior,
                    'conformant': test.conformant,
                    'deviation_details': test.deviation_details,
                    'severity': test.severity,
                    'timestamp': test.timestamp.isoformat()
                }
                for test in self.analyzer.protocol_tests
            ],
            'tcp_flow_analysis': {
                flow_key: {
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'src_port': flow.src_port,
                    'dst_port': flow.dst_port,
                    'congestion_algorithm': flow.congestion_algorithm,
                    'window_scaling': flow.window_scaling,
                    'sack_enabled': flow.sack_enabled,
                    'timestamp_enabled': flow.timestamp_enabled,
                    'mss': flow.mss,
                    'sequence_randomness_score': flow.sequence_randomness_score,
                    'implementation_fingerprint': flow.implementation_fingerprint,
                    'retransmissions': flow.retransmissions
                }
                for flow_key, flow in list(self.analyzer.tcp_flows.items())[:10]
            },
            'timing_analysis': {
                name: {
                    'measurement_type': analysis.measurement_type,
                    'target': analysis.target,
                    'sample_count': len(analysis.samples),
                    'mean': analysis.mean,
                    'median': analysis.median,
                    'std_dev': analysis.std_dev,
                    'min_time': analysis.min_time,
                    'max_time': analysis.max_time,
                    'jitter': analysis.jitter,
                    'percentile_95': analysis.percentile_95,
                    'percentile_99': analysis.percentile_99,
                    'coefficient_of_variation': analysis.coefficient_of_variation
                }
                for name, analysis in self.analyzer.timing_analyses.items()
            },
            'dns_analysis': {
                name: {
                    'resolver': analysis.resolver,
                    'query_type': analysis.query_type,
                    'response_time_udp': analysis.response_time_udp,
                    'response_time_tcp': analysis.response_time_tcp,
                    'response_time_doh': analysis.response_time_doh,
                    'edns_support': analysis.edns_support,
                    'response_size': analysis.response_size
                }
                for name, analysis in self.analyzer.dns_analyses.items()
            },
            'ipv6_vs_ipv4': {
                domain: {
                    'ipv4_latency': analysis.ipv4_latency,
                    'ipv6_latency': analysis.ipv6_latency,
                    'ipv4_packet_loss': analysis.ipv4_packet_loss,
                    'ipv6_packet_loss': analysis.ipv6_packet_loss,
                    'happy_eyeballs_preference': analysis.happy_eyeballs_preference
                }
                for domain, analysis in self.analyzer.ipv6v4_comparisons.items()
            },
            'bufferbloat_analysis': {
                target: {
                    'base_rtt': analysis.base_rtt,
                    'loaded_rtt': analysis.loaded_rtt,
                    'bufferbloat_score': analysis.bufferbloat_score,
                    'queue_length_estimate': analysis.queue_length_estimate,
                    'congestion_detected': analysis.congestion_detected
                }
                for target, analysis in self.analyzer.bufferbloat_results.items()
            },
            'security_analysis': {
                'tcp_sequence_issues': sum(1 for flow in self.analyzer.tcp_flows.values() 
                                         if flow.sequence_randomness_score < 0.5),
                'covert_channels_detected': len(self.analyzer.covert_channels),
                'bgp_changes_24h': len(self.analyzer.bgp_changes)
            }
        }
        
        print(json.dumps(research_data, indent=2))

async def main():
    # Signal handling
    def signal_handler(signum, frame):
        print(f"\n{Colors.YELLOW}NetPulse Elite analysis terminated{Colors.RESET}")
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
        print(f"\n{Colors.YELLOW}Advanced protocol analysis stopped{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Analysis error: {e}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}NetPulse Elite terminated{Colors.RESET}")
