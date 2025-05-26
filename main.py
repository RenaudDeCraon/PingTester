#!/usr/bin/env python3

import socket
import struct
import select
import time
import asyncio
import threading
import concurrent.futures
import random
import hashlib
import ssl
import json
import argparse
import sys
import os
import subprocess
import re
import sqlite3
import pickle
import logging
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple, Set, Any, Union, Callable
from collections import defaultdict, deque
import statistics
import ipaddress
from datetime import datetime, timedelta
import urllib.parse
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import configparser

import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import ARP
from scapy.packet import Raw
import requests
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.cluster import DBSCAN
import dns.resolver
import dns.reversename
import paramiko
import ftplib
import telnetlib3
import nmap
import pyshark

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    END = '\033[0m'

@dataclass
class ThreatIntelligence:
    ip_reputation: str
    malware_domains: List[str]
    threat_feeds: List[str]
    geolocation_risk: str
    known_vulnerabilities: List[str]
    security_headers: Dict[str, str]
    certificate_issues: List[str]

@dataclass
class NetworkInfrastructure:
    asn: str
    organization: str
    country: str
    city: str
    isp: str
    hosting_provider: str
    cloud_service: str
    cdn_provider: str
    network_type: str
    estimated_users: str

@dataclass
class WebApplicationDetails:
    technologies: List[str]
    frameworks: List[str]
    cms_detection: str
    javascript_libraries: List[str]
    analytics_trackers: List[str]
    advertising_networks: List[str]
    security_headers: Dict[str, str]
    cookies_analysis: Dict[str, Any]
    forms_detected: List[Dict]
    endpoints_discovered: List[str]

@dataclass
class ComprehensivePortAnalysis:
    port: int
    protocol: str
    state: str
    service: str
    version: str
    product: str
    banner: str
    response_analysis: Dict[str, Any]
    security_assessment: Dict[str, Any]
    protocol_compliance: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    threat_indicators: List[str]

@dataclass
class NetworkHost:
    ip: str
    hostname: str
    fqdn: List[str]
    operating_system: str
    device_type: str
    mac_address: str
    vendor: str
    network_info: NetworkInfrastructure
    threat_intel: ThreatIntelligence
    open_ports: List[ComprehensivePortAnalysis]
    web_applications: List[WebApplicationDetails]
    dns_records: Dict[str, List[str]]
    ssl_certificates: List[Dict[str, Any]]
    network_path: List[str]
    response_times: Dict[str, float]
    availability_score: float
    security_posture: str

@dataclass
class NetworkBaseline:
    target: str
    baseline_timestamp: datetime
    normal_services: List[int]
    normal_response_times: Dict[int, float]
    normal_ssl_config: Dict[str, Any]
    normal_dns_records: Dict[str, List[str]]
    traffic_patterns: Dict[str, Any]
    performance_metrics: Dict[str, float]
    security_posture: Dict[str, Any]

@dataclass
class ContinuousAlert:
    alert_id: str
    timestamp: datetime
    severity: str
    category: str
    target: str
    title: str
    description: str
    evidence: Dict[str, Any]
    recommended_actions: List[str]
    acknowledged: bool = False
    resolved: bool = False

@dataclass
class NetworkChangeEvent:
    event_id: str
    timestamp: datetime
    target: str
    change_type: str
    before_state: Dict[str, Any]
    after_state: Dict[str, Any]
    risk_level: str
    impact_assessment: str

@dataclass
class TrafficAnalysisResult:
    timestamp: datetime
    interface: str
    protocol_distribution: Dict[str, int]
    top_talkers: List[Tuple[str, int]]
    anomalous_traffic: List[Dict[str, Any]]
    threat_indicators: List[str]
    performance_metrics: Dict[str, float]
    bandwidth_utilization: float

class ComprehensiveReconnaissance:
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    async def gather_comprehensive_intelligence(self, target: str) -> Dict[str, Any]:
        print(f"{Colors.CYAN}🔍 Gathering comprehensive intelligence for {target}...{Colors.END}")
        
        intelligence = {}
        
        tasks = [
            self.dns_intelligence(target),
            self.whois_intelligence(target),
            self.certificate_intelligence(target),
            self.web_intelligence(target),
            self.network_infrastructure_analysis(target),
            self.threat_intelligence_lookup(target),
            self.subdomain_enumeration(target),
            self.technology_detection(target),
            self.social_media_presence(target),
            self.email_harvesting(target)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        intelligence['dns'] = results[0] if not isinstance(results[0], Exception) else {}
        intelligence['whois'] = results[1] if not isinstance(results[1], Exception) else {}
        intelligence['certificates'] = results[2] if not isinstance(results[2], Exception) else {}
        intelligence['web'] = results[3] if not isinstance(results[3], Exception) else {}
        intelligence['infrastructure'] = results[4] if not isinstance(results[4], Exception) else {}
        intelligence['threat_intel'] = results[5] if not isinstance(results[5], Exception) else {}
        intelligence['subdomains'] = results[6] if not isinstance(results[6], Exception) else {}
        intelligence['technology'] = results[7] if not isinstance(results[7], Exception) else {}
        intelligence['social'] = results[8] if not isinstance(results[8], Exception) else {}
        intelligence['emails'] = results[9] if not isinstance(results[9], Exception) else {}
        
        return intelligence
    
    async def dns_intelligence(self, target: str) -> Dict[str, Any]:
        dns_info = {
            'records': {},
            'nameservers': [],
            'mail_servers': [],
            'txt_records': [],
            'zone_transfer': False,
            'dns_security': {},
            'reverse_dns': {},
            'dns_history': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 10
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(target, record_type)
                    dns_info['records'][record_type] = []
                    for answer in answers:
                        dns_info['records'][record_type].append(str(answer))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    dns_info['records'][record_type] = []
            
            if 'NS' in dns_info['records']:
                dns_info['nameservers'] = dns_info['records']['NS']
            
            if 'MX' in dns_info['records']:
                dns_info['mail_servers'] = dns_info['records']['MX']
            
            if 'TXT' in dns_info['records']:
                dns_info['txt_records'] = dns_info['records']['TXT']
                for txt in dns_info['txt_records']:
                    if 'spf' in txt.lower():
                        dns_info['dns_security']['spf'] = txt
                    elif 'dmarc' in txt.lower():
                        dns_info['dns_security']['dmarc'] = txt
                    elif 'dkim' in txt.lower():
                        dns_info['dns_security']['dkim'] = txt
            
            if 'A' in dns_info['records']:
                for ip in dns_info['records']['A']:
                    try:
                        reverse = socket.gethostbyaddr(ip)[0]
                        dns_info['reverse_dns'][ip] = reverse
                    except:
                        dns_info['reverse_dns'][ip] = 'No reverse DNS'
            
            for ns in dns_info['nameservers'][:3]:
                try:
                    import dns.zone
                    import dns.query
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, target))
                    dns_info['zone_transfer'] = True
                    dns_info['zone_records'] = len(list(zone.nodes))
                    break
                except:
                    continue
            
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info
    
    async def whois_intelligence(self, target: str) -> Dict[str, Any]:
        whois_info = {}
        
        try:
            apis = [
                f'https://api.whoisjson.com/v1/{target}',
                f'https://whois.freeapi.app/api/whois?domainName={target}',
                f'https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={target}&outputFormat=JSON'
            ]
            
            for api in apis:
                try:
                    response = self.session.get(api, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        whois_info = data
                        break
                except:
                    continue
            
            if not whois_info:
                try:
                    result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        whois_info['raw'] = result.stdout
                except:
                    pass
        
        except Exception as e:
            whois_info['error'] = str(e)
        
        return whois_info
    
    async def certificate_intelligence(self, target: str) -> Dict[str, Any]:
        cert_info = {
            'certificates': [],
            'certificate_chain': [],
            'transparency_logs': [],
            'revocation_status': {},
            'security_analysis': {}
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info_dict = ssock.getpeercert()
                    
                    if cert_info_dict:
                        cert_info['certificates'].append({
                            'subject': dict(x[0] for x in cert_info_dict.get('subject', [])),
                            'issuer': dict(x[0] for x in cert_info_dict.get('issuer', [])),
                            'version': cert_info_dict.get('version'),
                            'serial_number': cert_info_dict.get('serialNumber'),
                            'not_before': cert_info_dict.get('notBefore'),
                            'not_after': cert_info_dict.get('notAfter'),
                            'signature_algorithm': cert_info_dict.get('signatureAlgorithm'),
                            'public_key_info': self.analyze_public_key(cert_der),
                            'extensions': cert_info_dict.get('extensions', [])
                        })
                    
                    cert_info['certificate_chain'] = self.get_certificate_chain(ssock)
                    
                    cert_info['security_analysis'] = {
                        'protocol_version': ssock.version(),
                        'cipher_suite': ssock.cipher(),
                        'key_exchange': self.analyze_key_exchange(ssock.cipher()),
                        'perfect_forward_secrecy': self.check_pfs(ssock.cipher()),
                        'certificate_transparency': self.check_ct_logs(cert_der)
                    }
        
        except Exception as e:
            cert_info['error'] = str(e)
        
        return cert_info
    
    def analyze_public_key(self, cert_der: bytes) -> Dict[str, Any]:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            cert = x509.load_der_x509_certificate(cert_der)
            public_key = cert.public_key()
            
            key_info = {
                'algorithm': type(public_key).__name__,
                'key_size': getattr(public_key, 'key_size', 'Unknown')
            }
            
            if hasattr(public_key, 'public_numbers'):
                key_info['public_numbers'] = str(public_key.public_numbers())
            
            return key_info
        except:
            return {'error': 'Unable to analyze public key'}
    
    def get_certificate_chain(self, ssl_socket) -> List[Dict]:
        try:
            chain = ssl_socket.getpeercert_chain()
            if chain:
                return [{'subject': cert.get_subject().get_components()} for cert in chain]
        except:
            pass
        return []
    
    def analyze_key_exchange(self, cipher_info: tuple) -> str:
        if cipher_info and len(cipher_info) > 0:
            cipher_name = cipher_info[0].lower()
            if 'ecdhe' in cipher_name:
                return 'ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)'
            elif 'dhe' in cipher_name:
                return 'DHE (Diffie-Hellman Ephemeral)'
            elif 'ecdh' in cipher_name:
                return 'ECDH (Elliptic Curve Diffie-Hellman)'
            elif 'dh' in cipher_name:
                return 'DH (Diffie-Hellman)'
            elif 'rsa' in cipher_name:
                return 'RSA'
        return 'Unknown'
    
    def check_pfs(self, cipher_info: tuple) -> bool:
        if cipher_info and len(cipher_info) > 0:
            cipher_name = cipher_info[0].lower()
            return 'ecdhe' in cipher_name or 'dhe' in cipher_name
        return False
    
    def check_ct_logs(self, cert_der: bytes) -> bool:
        return True
    
    async def web_intelligence(self, target: str) -> Dict[str, Any]:
        web_info = {
            'http_analysis': {},
            'https_analysis': {},
            'headers': {},
            'cookies': {},
            'technologies': [],
            'security_headers': {},
            'forms': [],
            'links': [],
            'javascript': [],
            'content_analysis': {}
        }
        
        try:
            try:
                http_response = self.session.get(f'http://{target}', timeout=10, allow_redirects=False)
                web_info['http_analysis'] = {
                    'status_code': http_response.status_code,
                    'headers': dict(http_response.headers),
                    'redirect_location': http_response.headers.get('Location', ''),
                    'content_length': len(http_response.content),
                    'response_time': http_response.elapsed.total_seconds()
                }
            except:
                web_info['http_analysis'] = {'error': 'HTTP not accessible'}
            
            try:
                https_response = self.session.get(f'https://{target}', timeout=10)
                web_info['https_analysis'] = {
                    'status_code': https_response.status_code,
                    'headers': dict(https_response.headers),
                    'content_length': len(https_response.content),
                    'response_time': https_response.elapsed.total_seconds(),
                    'final_url': https_response.url
                }
                
                if https_response.content:
                    web_info['content_analysis'] = self.analyze_html_content(https_response.text)
                
                web_info['security_headers'] = self.analyze_security_headers(https_response.headers)
                
                web_info['cookies'] = self.analyze_cookies(https_response.cookies)
                
            except Exception as e:
                web_info['https_analysis'] = {'error': str(e)}
        
        except Exception as e:
            web_info['error'] = str(e)
        
        return web_info
    
    def analyze_html_content(self, html_content: str) -> Dict[str, Any]:
        analysis = {
            'title': '',
            'meta_tags': [],
            'scripts': [],
            'forms': [],
            'links': [],
            'technologies': [],
            'potential_vulnerabilities': []
        }
        
        try:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if title_match:
                analysis['title'] = title_match.group(1).strip()
            
            meta_matches = re.finditer(r'<meta[^>]+>', html_content, re.IGNORECASE)
            for match in meta_matches:
                analysis['meta_tags'].append(match.group(0))
            
            script_matches = re.finditer(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', html_content, re.IGNORECASE)
            for match in script_matches:
                analysis['scripts'].append(match.group(1))
            
            form_matches = re.finditer(r'<form[^>]*>(.*?)</form>', html_content, re.IGNORECASE | re.DOTALL)
            for match in form_matches:
                analysis['forms'].append(match.group(0))
            
            tech_patterns = {
                'jQuery': r'jquery',
                'React': r'react',
                'Angular': r'angular',
                'Vue.js': r'vue\.js',
                'Bootstrap': r'bootstrap',
                'WordPress': r'wp-content|wp-includes',
                'Drupal': r'drupal',
                'Joomla': r'joomla'
            }
            
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, html_content, re.IGNORECASE):
                    analysis['technologies'].append(tech)
            
            vuln_patterns = [
                (r'<script[^>]*>.*?alert\s*\(', 'Potential XSS vulnerability'),
                (r'sql\s*=\s*["\'].*?["\']', 'Potential SQL injection'),
                (r'eval\s*\(', 'Use of eval() function'),
                (r'innerHTML\s*=', 'Potential DOM manipulation'),
                (r'document\.write\s*\(', 'Use of document.write()')
            ]
            
            for pattern, description in vuln_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    analysis['potential_vulnerabilities'].append(description)
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def analyze_security_headers(self, headers: Dict) -> Dict[str, Any]:
        security_analysis = {
            'present': [],
            'missing': [],
            'analysis': {}
        }
        
        important_headers = {
            'Strict-Transport-Security': 'HSTS - Enforces HTTPS connections',
            'Content-Security-Policy': 'CSP - Prevents XSS attacks',
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-XSS-Protection': 'XSS protection (legacy)',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features',
            'Content-Type': 'Specifies content type'
        }
        
        for header, description in important_headers.items():
            if header in headers or header.lower() in [h.lower() for h in headers.keys()]:
                security_analysis['present'].append({
                    'header': header,
                    'value': headers.get(header, ''),
                    'description': description
                })
            else:
                security_analysis['missing'].append({
                    'header': header,
                    'description': description,
                    'risk': 'Security header not implemented'
                })
        
        return security_analysis
    
    def analyze_cookies(self, cookies) -> Dict[str, Any]:
        cookie_analysis = {
            'total_cookies': 0,
            'secure_cookies': 0,
            'httponly_cookies': 0,
            'samesite_cookies': 0,
            'cookies': []
        }
        
        if cookies:
            cookie_analysis['total_cookies'] = len(cookies)
            
            for cookie in cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': hasattr(cookie, 'httponly') and cookie.httponly,
                    'samesite': getattr(cookie, 'samesite', None)
                }
                
                cookie_analysis['cookies'].append(cookie_info)
                
                if cookie.secure:
                    cookie_analysis['secure_cookies'] += 1
                if hasattr(cookie, 'httponly') and cookie.httponly:
                    cookie_analysis['httponly_cookies'] += 1
                if getattr(cookie, 'samesite', None):
                    cookie_analysis['samesite_cookies'] += 1
        
        return cookie_analysis
    
    async def network_infrastructure_analysis(self, target: str) -> Dict[str, Any]:
        infrastructure = {
            'ip_addresses': [],
            'asn_info': {},
            'geolocation': {},
            'hosting_info': {},
            'cdn_detection': {},
            'cloud_services': []
        }
        
        try:
            ip_addresses = []
            try:
                ipv4_addr = socket.gethostbyname(target)
                ip_addresses.append(ipv4_addr)
            except:
                pass
            
            try:
                ipv6_info = socket.getaddrinfo(target, None, socket.AF_INET6)
                for info in ipv6_info:
                    ip_addresses.append(info[4][0])
            except:
                pass
            
            infrastructure['ip_addresses'] = list(set(ip_addresses))
            
            for ip in infrastructure['ip_addresses'][:3]:
                try:
                    response = self.session.get(f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,hosting', timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('status') == 'success':
                            infrastructure['asn_info'][ip] = {
                                'asn': data.get('as', ''),
                                'asn_name': data.get('asname', ''),
                                'organization': data.get('org', ''),
                                'isp': data.get('isp', '')
                            }
                            
                            infrastructure['geolocation'][ip] = {
                                'country': data.get('country', ''),
                                'country_code': data.get('countryCode', ''),
                                'region': data.get('regionName', ''),
                                'city': data.get('city', ''),
                                'latitude': data.get('lat', ''),
                                'longitude': data.get('lon', ''),
                                'timezone': data.get('timezone', ''),
                                'is_hosting': data.get('hosting', False)
                            }
                except:
                    continue
            
            infrastructure['cdn_detection'] = await self.detect_cdn(target)
            
            infrastructure['cloud_services'] = self.detect_cloud_services(infrastructure['asn_info'])
        
        except Exception as e:
            infrastructure['error'] = str(e)
        
        return infrastructure
    
    async def detect_cdn(self, target: str) -> Dict[str, Any]:
        cdn_info = {
            'detected': False,
            'provider': 'Unknown',
            'indicators': []
        }
        
        try:
            try:
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(target, 'CNAME')
                for answer in answers:
                    cname = str(answer).lower()
                    
                    cdn_patterns = {
                        'cloudflare': ['cloudflare.com', 'cloudflare.net'],
                        'fastly': ['fastly.com', 'fastly.net'],
                        'amazon_cloudfront': ['cloudfront.net', 'amazonaws.com'],
                        'google_cloud_cdn': ['googleusercontent.com', 'gstatic.com'],
                        'microsoft_azure': ['azureedge.net', 'azure.com'],
                        'akamai': ['akamai.net', 'akamaitech.net'],
                        'keycdn': ['keycdn.com'],
                        'maxcdn': ['maxcdn.com'],
                        'jsdelivr': ['jsdelivr.net']
                    }
                    
                    for cdn, patterns in cdn_patterns.items():
                        for pattern in patterns:
                            if pattern in cname:
                                cdn_info['detected'] = True
                                cdn_info['provider'] = cdn.replace('_', ' ').title()
                                cdn_info['indicators'].append(f'CNAME points to {cname}')
                                break
            except:
                pass
            
            try:
                response = self.session.head(f'https://{target}', timeout=5)
                headers = response.headers
                
                cdn_headers = {
                    'cf-ray': 'Cloudflare',
                    'x-served-by': 'Fastly',
                    'x-cache': 'Various CDNs',
                    'x-amz-cf-id': 'Amazon CloudFront',
                    'x-azure-ref': 'Microsoft Azure CDN'
                }
                
                for header, provider in cdn_headers.items():
                    if header in headers:
                        cdn_info['detected'] = True
                        if cdn_info['provider'] == 'Unknown':
                            cdn_info['provider'] = provider
                        cdn_info['indicators'].append(f'Header: {header}')
            except:
                pass
        
        except Exception as e:
            cdn_info['error'] = str(e)
        
        return cdn_info
    
    def detect_cloud_services(self, asn_info: Dict) -> List[str]:
        cloud_services = []
        
        cloud_patterns = {
            'Amazon Web Services': ['amazon', 'aws', 'ec2'],
            'Google Cloud Platform': ['google', 'gcp', 'googleapis'],
            'Microsoft Azure': ['microsoft', 'azure'],
            'DigitalOcean': ['digitalocean'],
            'Linode': ['linode'],
            'Vultr': ['vultr'],
            'Hetzner': ['hetzner'],
            'OVH': ['ovh']
        }
        
        for ip, info in asn_info.items():
            org_lower = info.get('organization', '').lower()
            isp_lower = info.get('isp', '').lower()
            
            for cloud, patterns in cloud_patterns.items():
                for pattern in patterns:
                    if pattern in org_lower or pattern in isp_lower:
                        if cloud not in cloud_services:
                            cloud_services.append(cloud)
                        break
        
        return cloud_services
    
    async def threat_intelligence_lookup(self, target: str) -> Dict[str, Any]:
        threat_info = {
            'reputation': 'Clean',
            'threat_feeds': [],
            'malware_associations': [],
            'phishing_detection': False,
            'blocklists': [],
            'security_vendors': {}
        }
        
        try:
            ip_addresses = []
            try:
                ip_addresses.append(socket.gethostbyname(target))
            except:
                pass
            
            for ip in ip_addresses:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    
                    if ip_obj.is_private:
                        threat_info['reputation'] = 'Private Network'
                    elif str(ip_obj).startswith(('1.1.1.', '8.8.8.', '8.8.4.4')):
                        threat_info['reputation'] = 'Public DNS Service'
                    else:
                        threat_info['reputation'] = 'Clean'
                
                except:
                    pass
        
        except Exception as e:
            threat_info['error'] = str(e)
        
        return threat_info
    
    async def subdomain_enumeration(self, target: str) -> Dict[str, Any]:
        subdomains = {
            'discovered': [],
            'active': [],
            'technologies': {},
            'certificates': {}
        }
        
        try:
            common_subs = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
                'cdn', 'blog', 'shop', 'forum', 'support', 'secure', 'vpn',
                'portal', 'app', 'mobile', 'm', 'beta', 'alpha', 'demo',
                'login', 'auth', 'oauth', 'sso', 'dashboard', 'panel',
                'cpanel', 'webmail', 'pop', 'imap', 'smtp', 'mx', 'ns1', 'ns2'
            ]
            
            for sub in common_subs:
                try:
                    full_domain = f"{sub}.{target}"
                    ip = socket.gethostbyname(full_domain)
                    subdomains['discovered'].append({
                        'domain': full_domain,
                        'ip': ip,
                        'type': 'A'
                    })
                    
                    is_active = await self.check_subdomain_active(full_domain)
                    if is_active:
                        subdomains['active'].append(full_domain)
                    
                    await asyncio.sleep(0.1)
                
                except:
                    continue
                
                if len(subdomains['discovered']) >= 20:
                    break
            
        except Exception as e:
            subdomains['error'] = str(e)
        
        return subdomains
    
    async def check_subdomain_active(self, subdomain: str) -> bool:
        try:
            response = self.session.head(f'https://{subdomain}', timeout=3)
            return response.status_code < 400
        except:
            try:
                response = self.session.head(f'http://{subdomain}', timeout=3)
                return response.status_code < 400
            except:
                return False
    
    async def technology_detection(self, target: str) -> Dict[str, Any]:
        tech_info = {
            'web_server': 'Unknown',
            'programming_languages': [],
            'frameworks': [],
            'cms': 'Unknown',
            'analytics': [],
            'cdn': 'Unknown',
            'javascript_libraries': [],
            'css_frameworks': []
        }
        
        try:
            response = self.session.get(f'https://{target}', timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            server_header = headers.get('Server', '').lower()
            if 'nginx' in server_header:
                tech_info['web_server'] = 'Nginx'
            elif 'apache' in server_header:
                tech_info['web_server'] = 'Apache'
            elif 'iis' in server_header:
                tech_info['web_server'] = 'IIS'
            elif 'cloudflare' in server_header:
                tech_info['web_server'] = 'Cloudflare'
            
            framework_patterns = {
                'django': 'Django',
                'flask': 'Flask',
                'express': 'Express.js',
                'laravel': 'Laravel',
                'symfony': 'Symfony',
                'spring': 'Spring',
                'asp.net': 'ASP.NET',
                'rails': 'Ruby on Rails'
            }
            
            for pattern, framework in framework_patterns.items():
                if pattern in content or pattern in str(headers).lower():
                    tech_info['frameworks'].append(framework)
            
            cms_patterns = {
                'wp-content': 'WordPress',
                'drupal': 'Drupal',
                'joomla': 'Joomla',
                'magento': 'Magento',
                'shopify': 'Shopify'
            }
            
            for pattern, cms in cms_patterns.items():
                if pattern in content:
                    tech_info['cms'] = cms
                    break
            
            js_patterns = {
                'jquery': 'jQuery',
                'react': 'React',
                'angular': 'Angular',
                'vue': 'Vue.js',
                'bootstrap': 'Bootstrap',
                'd3': 'D3.js',
                'lodash': 'Lodash'
            }
            
            for pattern, library in js_patterns.items():
                if pattern in content:
                    tech_info['javascript_libraries'].append(library)
            
            analytics_patterns = {
                'google-analytics': 'Google Analytics',
                'gtag': 'Google Analytics',
                'facebook.com/tr': 'Facebook Pixel',
                'hotjar': 'Hotjar',
                'mixpanel': 'Mixpanel'
            }
            
            for pattern, analytics in analytics_patterns.items():
                if pattern in content:
                    tech_info['analytics'].append(analytics)
        
        except Exception as e:
            tech_info['error'] = str(e)
        
        return tech_info
    
    async def social_media_presence(self, target: str) -> Dict[str, Any]:
        social = {
            'platforms': [],
            'links_found': []
        }
        
        try:
            response = self.session.get(f'https://{target}', timeout=10)
            content = response.text.lower()
            
            social_patterns = {
                'facebook.com': 'Facebook',
                'twitter.com': 'Twitter',
                'linkedin.com': 'LinkedIn',
                'instagram.com': 'Instagram',
                'youtube.com': 'YouTube',
                'github.com': 'GitHub'
            }
            
            for pattern, platform in social_patterns.items():
                if pattern in content:
                    social['platforms'].append(platform)
                    links = re.findall(f'https?://[^\\s]*{pattern}[^\\s]*', content)
                    social['links_found'].extend(links[:3])
        
        except Exception as e:
            social['error'] = str(e)
        
        return social
    
    async def email_harvesting(self, target: str) -> Dict[str, Any]:
        emails = {
            'addresses': [],
            'patterns': []
        }
        
        try:
            response = self.session.get(f'https://{target}', timeout=10)
            content = response.text
            
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            found_emails = re.findall(email_pattern, content)
            
            filtered_emails = []
            for email in found_emails:
                if not any(x in email.lower() for x in ['example', 'test', 'noreply', 'no-reply']):
                    filtered_emails.append(email)
            
            emails['addresses'] = list(set(filtered_emails))[:10]
            
            domains = [email.split('@')[1] for email in emails['addresses']]
            domain_counts = {}
            for domain in domains:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
            
            emails['patterns'] = domain_counts
        
        except Exception as e:
            emails['error'] = str(e)
        
        return emails

class AdvancedPortScanner:
    
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.common_ports = list(range(1, 1025))
        
    async def comprehensive_port_scan(self, target: str) -> List[ComprehensivePortAnalysis]:
        print(f"{Colors.CYAN}🔍 Performing comprehensive port analysis...{Colors.END}")
        
        results = []
        
        try:
            print(f"  → Running initial port discovery...")
            scan_result = self.nmap_scanner.scan(target, '1-65535', arguments='-sS -T4 --open')
            
            if target in scan_result['scan']:
                host_info = scan_result['scan'][target]
                if 'tcp' in host_info:
                    open_ports = list(host_info['tcp'].keys())
                    print(f"  → Found {len(open_ports)} open ports")
                    
                    for port in open_ports[:50]:
                        port_analysis = await self.analyze_port_comprehensive(target, port)
                        results.append(port_analysis)
                        
                        service = port_analysis.service
                        version = port_analysis.version
                        print(f"    {port:5d}/tcp {Colors.GREEN}open{Colors.END} {service:15s} {version}")
        
        except Exception as e:
            print(f"  {Colors.RED}Port scanning error: {e}{Colors.END}")
        
        return results
    
    async def analyze_port_comprehensive(self, target: str, port: int) -> ComprehensivePortAnalysis:
        
        analysis = ComprehensivePortAnalysis(
            port=port,
            protocol='tcp',
            state='unknown',
            service='unknown',
            version='',
            product='',
            banner='',
            response_analysis={},
            security_assessment={},
            protocol_compliance={},
            performance_metrics={},
            threat_indicators=[]
        )
        
        try:
            start_time = time.time()
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=5
            )
            
            connection_time = (time.time() - start_time) * 1000
            analysis.state = 'open'
            
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=3)
                analysis.banner = banner.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                pass
            
            service_info = await self.identify_service(reader, writer, port, target)
            analysis.service = service_info.get('name', 'unknown')
            analysis.version = service_info.get('version', '')
            analysis.product = service_info.get('product', '')
            
            analysis.performance_metrics = {
                'connection_time_ms': connection_time,
                'banner_response_time': connection_time,
                'keep_alive_supported': False
            }
            
            analysis.security_assessment = await self.assess_port_security(
                target, port, analysis.service, analysis.banner
            )
            
            analysis.protocol_compliance = await self.test_protocol_compliance(
                reader, writer, port, analysis.service
            )
            
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            analysis.state = 'filtered'
        except ConnectionRefusedError:
            analysis.state = 'closed'
        except Exception as e:
            analysis.state = 'error'
            analysis.threat_indicators.append(f"Connection error: {str(e)}")
        
        return analysis
    
    async def identify_service(self, reader, writer, port: int, target: str) -> Dict[str, str]:
        service_info = {'name': 'unknown', 'version': '', 'product': ''}
        
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 993: 'imaps',
            995: 'pop3s', 3389: 'rdp', 5432: 'postgresql', 3306: 'mysql'
        }
        
        service_info['name'] = common_services.get(port, 'unknown')
        
        if port == 80 or port == 8080:
            service_info.update(await self.probe_http_service(reader, writer, target, port))
        elif port == 443 or port == 8443:
            service_info.update(await self.probe_https_service(target, port))
        elif port == 22:
            service_info.update(await self.probe_ssh_service(reader, writer))
        elif port == 21:
            service_info.update(await self.probe_ftp_service(reader, writer))
        elif port == 25:
            service_info.update(await self.probe_smtp_service(reader, writer, target))
        
        return service_info
    
    async def probe_http_service(self, reader, writer, target: str, port: int) -> Dict[str, str]:
        info = {}
        
        try:
            request = f'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: NetPulse-Elite\r\nConnection: close\r\n\r\n'
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            response_str = response.decode('utf-8', errors='ignore')
            
            lines = response_str.split('\r\n')
            if lines and 'HTTP/' in lines[0]:
                info['name'] = 'http'
                
                for line in lines:
                    if line.lower().startswith('server:'):
                        server_info = line.split(':', 1)[1].strip()
                        info['product'] = server_info
                        
                        if '/' in server_info:
                            info['version'] = server_info.split('/')[1].split()[0]
                        break
        
        except Exception:
            pass
        
        return info
    
    async def probe_https_service(self, target: str, port: int) -> Dict[str, str]:
        info = {'name': 'https'}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    info['version'] = ssock.version()
                    
                    request = f'GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n'
                    ssock.send(request.encode())
                    
                    response = ssock.recv(4096).decode('utf-8', errors='ignore')
                    for line in response.split('\r\n'):
                        if line.lower().startswith('server:'):
                            info['product'] = line.split(':', 1)[1].strip()
                            break
        
        except Exception:
            pass
        
        return info
    
    async def probe_ssh_service(self, reader, writer) -> Dict[str, str]:
        info = {'name': 'ssh'}
        
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            if banner_str.startswith('SSH-'):
                parts = banner_str.split('-')
                if len(parts) >= 3:
                    info['version'] = parts[1]
                    info['product'] = parts[2].split()[0] if parts[2] else 'unknown'
        
        except Exception:
            pass
        
        return info
    
    async def probe_ftp_service(self, reader, writer) -> Dict[str, str]:
        info = {'name': 'ftp'}
        
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            if '220' in banner_str:
                if 'vsftpd' in banner_str.lower():
                    info['product'] = 'vsftpd'
                elif 'proftpd' in banner_str.lower():
                    info['product'] = 'ProFTPD'
                elif 'filezilla' in banner_str.lower():
                    info['product'] = 'FileZilla Server'
        
        except Exception:
            pass
        
        return info
    
    async def probe_smtp_service(self, reader, writer, target: str) -> Dict[str, str]:
        info = {'name': 'smtp'}
        
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            if '220' in banner_str:
                writer.write(f'EHLO {target}\r\n'.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=3)
                response_str = response.decode('utf-8', errors='ignore')
                
                if 'postfix' in response_str.lower():
                    info['product'] = 'Postfix'
                elif 'sendmail' in response_str.lower():
                    info['product'] = 'Sendmail'
                elif 'exim' in response_str.lower():
                    info['product'] = 'Exim'
        
        except Exception:
            pass
        
        return info
    
    async def assess_port_security(self, target: str, port: int, service: str, banner: str) -> Dict[str, Any]:
        security = {
            'risk_level': 'Low',
            'vulnerabilities': [],
            'recommendations': [],
            'encryption_status': 'Unknown',
            'authentication_required': 'Unknown'
        }
        
        if service == 'http':
            security['risk_level'] = 'Medium'
            security['vulnerabilities'].append('Unencrypted HTTP traffic')
            security['recommendations'].append('Implement HTTPS')
            security['encryption_status'] = 'None'
        
        elif service == 'https':
            security['risk_level'] = 'Low'
            security['encryption_status'] = 'TLS/SSL'
        
        elif service == 'ssh':
            security['risk_level'] = 'Low'
            security['encryption_status'] = 'SSH'
            security['authentication_required'] = 'Yes'
            
            if 'openssh' in banner.lower():
                version_match = re.search(r'openssh[_\s]+([\d.]+)', banner.lower())
                if version_match:
                    version = version_match.group(1)
                    if version.startswith('6.') or version.startswith('7.'):
                        security['vulnerabilities'].append(f'OpenSSH {version} may have known vulnerabilities')
        
        elif service == 'ftp':
            security['risk_level'] = 'High'
            security['vulnerabilities'].append('Unencrypted FTP protocol')
            security['recommendations'].append('Use SFTP or FTPS instead')
            security['encryption_status'] = 'None'
        
        elif service == 'telnet':
            security['risk_level'] = 'Critical'
            security['vulnerabilities'].append('Unencrypted Telnet protocol')
            security['recommendations'].append('Use SSH instead of Telnet')
            security['encryption_status'] = 'None'
        
        if port in [21, 23, 25, 53, 80, 110, 143]:
            if service not in ['https', 'ssh']:
                security['recommendations'].append('Consider implementing encryption')
        
        return security
    
    async def test_protocol_compliance(self, reader, writer, port: int, service: str) -> Dict[str, Any]:
        compliance = {
            'rfc_compliant': 'Unknown',
            'standards_followed': [],
            'deviations_found': [],
            'protocol_version': 'Unknown'
        }
        
        if service == 'http':
            compliance.update(await self.test_http_compliance(reader, writer))
        elif service == 'smtp':
            compliance.update(await self.test_smtp_compliance(reader, writer))
        
        return compliance
    
    async def test_http_compliance(self, reader, writer) -> Dict[str, Any]:
        compliance = {'rfc_compliant': 'Partial', 'standards_followed': ['HTTP/1.1']}
        
        try:
            test_methods = ['GET', 'HEAD', 'OPTIONS']
            
            for method in test_methods:
                request = f'{method} / HTTP/1.1\r\nHost: test\r\n\r\n'
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=2)
                response_str = response.decode('utf-8', errors='ignore')
                
                if 'HTTP/' in response_str:
                    compliance['standards_followed'].append(f'{method} method supported')
                
                break
        
        except Exception:
            compliance['rfc_compliant'] = 'Unknown'
        
        return compliance
    
    async def test_smtp_compliance(self, reader, writer) -> Dict[str, Any]:
        compliance = {'rfc_compliant': 'Partial', 'standards_followed': ['SMTP']}
        
        try:
            commands = ['EHLO test', 'HELP', 'NOOP']
            
            for command in commands:
                writer.write(f'{command}\r\n'.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=2)
                response_str = response.decode('utf-8', errors='ignore')
                
                if response_str.startswith(('250', '214', '502')):
                    compliance['standards_followed'].append(f'{command} command')
        
        except Exception:
            compliance['rfc_compliant'] = 'Unknown'
        
        return compliance

class IntelligentSecurityAssessment:
    
    def __init__(self):
        self.risk_weights = {
            'vulnerability_count': 0.3,
            'service_exposure': 0.2,
            'encryption_status': 0.2,
            'service_security': 0.2,
            'threat_indicators': 0.1
        }
    
    def assess_comprehensive_security(self, network_host: NetworkHost, 
                                   reconnaissance_data: Dict) -> Dict[str, Any]:
        
        assessment = {
            'overall_score': 0,
            'risk_level': 'Unknown',
            'security_posture': 'Unknown',
            'detailed_analysis': {},
            'recommendations': [],
            'compliance_status': {},
            'threat_landscape': {}
        }
        
        assessment['detailed_analysis'] = {
            'service_security': self.analyze_service_security(network_host.open_ports),
            'network_exposure': self.analyze_network_exposure(network_host),
            'encryption_analysis': self.analyze_encryption_status(network_host.open_ports),
            'vulnerability_assessment': self.analyze_vulnerabilities(network_host.open_ports),
            'infrastructure_security': self.analyze_infrastructure_security(reconnaissance_data),
            'web_security': self.analyze_web_security(network_host.web_applications)
        }
        
        assessment['overall_score'] = self.calculate_intelligent_score(
            network_host, reconnaissance_data, assessment['detailed_analysis']
        )
        
        assessment['risk_level'] = self.determine_intelligent_risk_level(
            assessment['overall_score'], assessment['detailed_analysis']
        )
        
        assessment['recommendations'] = self.generate_intelligent_recommendations(
            assessment['detailed_analysis'], network_host
        )
        
        assessment['security_posture'] = self.assess_security_posture(
            assessment['overall_score'], assessment['detailed_analysis']
        )
        
        return assessment
    
    def calculate_intelligent_score(self, network_host: NetworkHost, 
                                   recon_data: Dict, detailed_analysis: Dict) -> int:
        
        base_score = 70
        
        service_analysis = detailed_analysis['service_security']
        if service_analysis['secure_services'] > service_analysis['insecure_services']:
            base_score += 10
        elif service_analysis['insecure_services'] > 0:
            base_score -= min(service_analysis['insecure_services'] * 5, 20)
        
        encryption_analysis = detailed_analysis['encryption_analysis']
        encryption_ratio = encryption_analysis['encrypted_services'] / max(len(network_host.open_ports), 1)
        base_score += int(encryption_ratio * 15)
        
        vuln_analysis = detailed_analysis['vulnerability_assessment']
        critical_vulns = vuln_analysis['critical_vulnerabilities']
        high_vulns = vuln_analysis['high_vulnerabilities']
        
        base_score -= min(critical_vulns * 15, 30)
        base_score -= min(high_vulns * 8, 20)
        
        infra_analysis = detailed_analysis['infrastructure_security']
        if infra_analysis['cdn_protection']:
            base_score += 5
        if infra_analysis['cloud_security_features']:
            base_score += 5
        
        web_analysis = detailed_analysis['web_security']
        if web_analysis['security_headers_score'] > 70:
            base_score += 10
        elif web_analysis['security_headers_score'] < 30:
            base_score -= 10
        
        if self.is_well_known_secure_service(network_host, recon_data):
            base_score = max(base_score, 75)
        
        return max(0, min(100, base_score))
    
    def is_well_known_secure_service(self, network_host: NetworkHost, recon_data: Dict) -> bool:
        
        secure_indicators = [
            'google', 'cloudflare', 'amazon', 'microsoft', 'github',
            'stackoverflow', 'reddit', 'twitter', 'facebook', 'linkedin'
        ]
        
        hostname = network_host.hostname.lower()
        for indicator in secure_indicators:
            if indicator in hostname:
                return True
        
        infra = network_host.network_info
        if infra:
            org_lower = infra.organization.lower()
            for indicator in secure_indicators:
                if indicator in org_lower:
                    return True
        
        if recon_data.get('certificates', {}).get('certificates'):
            cert = recon_data['certificates']['certificates'][0]
            if cert.get('issuer', {}).get('organizationName'):
                issuer = cert['issuer']['organizationName'].lower()
                if any(x in issuer for x in ['digicert', 'sectigo', 'globalsign', 'godaddy']):
                    return True
        
        return False
    
    def determine_intelligent_risk_level(self, score: int, detailed_analysis: Dict) -> str:
        
        if score >= 80:
            base_risk = 'Low'
        elif score >= 65:
            base_risk = 'Medium-Low'
        elif score >= 50:
            base_risk = 'Medium'
        elif score >= 35:
            base_risk = 'Medium-High'
        else:
            base_risk = 'High'
        
        vuln_analysis = detailed_analysis['vulnerability_assessment']
        if vuln_analysis['critical_vulnerabilities'] > 0:
            if base_risk in ['Low', 'Medium-Low']:
                base_risk = 'Medium'
        
        service_analysis = detailed_analysis['service_security']
        if service_analysis['critical_services'] > 0:
            if base_risk == 'Low':
                base_risk = 'Medium-Low'
        
        return base_risk
    
    def analyze_service_security(self, ports: List[ComprehensivePortAnalysis]) -> Dict[str, Any]:
        
        analysis = {
            'total_services': len(ports),
            'secure_services': 0,
            'insecure_services': 0,
            'critical_services': 0,
            'service_breakdown': {},
            'security_issues': []
        }
        
        secure_services = ['https', 'ssh', 'imaps', 'pop3s', 'smtps']
        insecure_services = ['http', 'ftp', 'telnet']
        critical_services = ['telnet', 'ftp']
        
        for port_analysis in ports:
            service = port_analysis.service
            
            analysis['service_breakdown'][service] = analysis['service_breakdown'].get(service, 0) + 1
            
            if service in secure_services:
                analysis['secure_services'] += 1
            elif service in insecure_services:
                analysis['insecure_services'] += 1
                
                if service == 'http' and port_analysis.port == 80:
                    if 'redirect' not in str(port_analysis.response_analysis).lower():
                        analysis['security_issues'].append(f'HTTP service on port {port_analysis.port} without HTTPS redirect')
                elif service in critical_services:
                    analysis['critical_services'] += 1
                    analysis['security_issues'].append(f'Critical insecure service: {service} on port {port_analysis.port}')
        
        return analysis
    
    def analyze_network_exposure(self, network_host: NetworkHost) -> Dict[str, Any]:
        
        analysis = {
            'total_open_ports': len(network_host.open_ports),
            'attack_surface_score': 0,
            'exposed_services': [],
            'internal_services_exposed': [],
            'unnecessary_services': []
        }
        
        analysis['attack_surface_score'] = min(len(network_host.open_ports) * 2, 50)
        
        for port_analysis in network_host.open_ports:
            if port_analysis.state == 'open':
                analysis['exposed_services'].append({
                    'port': port_analysis.port,
                    'service': port_analysis.service,
                    'risk_level': port_analysis.security_assessment.get('risk_level', 'Unknown')
                })
        
        internal_ports = [3306, 5432, 6379, 27017, 1433, 5984]
        for port_analysis in network_host.open_ports:
            if port_analysis.port in internal_ports:
                analysis['internal_services_exposed'].append({
                    'port': port_analysis.port,
                    'service': port_analysis.service
                })
        
        return analysis
    
    def analyze_encryption_status(self, ports: List[ComprehensivePortAnalysis]) -> Dict[str, Any]:
        
        analysis = {
            'total_services': len(ports),
            'encrypted_services': 0,
            'unencrypted_services': 0,
            'encryption_ratio': 0.0,
            'encryption_details': []
        }
        
        encrypted_services = ['https', 'ssh', 'imaps', 'pop3s', 'smtps']
        
        for port_analysis in ports:
            service = port_analysis.service
            
            if service in encrypted_services:
                analysis['encrypted_services'] += 1
                analysis['encryption_details'].append({
                    'port': port_analysis.port,
                    'service': service,
                    'encryption_type': self.get_encryption_type(service)
                })
            else:
                analysis['unencrypted_services'] += 1
        
        if analysis['total_services'] > 0:
            analysis['encryption_ratio'] = analysis['encrypted_services'] / analysis['total_services']
        
        return analysis
    
    def get_encryption_type(self, service: str) -> str:
        encryption_map = {
            'https': 'TLS/SSL',
            'ssh': 'SSH',
            'imaps': 'TLS/SSL',
            'pop3s': 'TLS/SSL',
            'smtps': 'TLS/SSL'
        }
        return encryption_map.get(service, 'Unknown')
    
    def analyze_vulnerabilities(self, ports: List[ComprehensivePortAnalysis]) -> Dict[str, Any]:
        
        analysis = {
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'false_positives_filtered': 0,
            'vulnerability_details': []
        }
        
        for port_analysis in ports:
            security_assessment = port_analysis.security_assessment
            vulnerabilities = security_assessment.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                if self.is_significant_vulnerability(vuln, port_analysis):
                    severity = self.classify_vulnerability_severity(vuln, port_analysis)
                    
                    analysis['total_vulnerabilities'] += 1
                    analysis[f'{severity}_vulnerabilities'] += 1
                    
                    analysis['vulnerability_details'].append({
                        'port': port_analysis.port,
                        'service': port_analysis.service,
                        'vulnerability': vuln,
                        'severity': severity
                    })
                else:
                    analysis['false_positives_filtered'] += 1
        
        return analysis
    
    def is_significant_vulnerability(self, vulnerability: str, port_analysis: ComprehensivePortAnalysis) -> bool:
        
        vuln_lower = vulnerability.lower()
        
        false_positive_patterns = [
            'server header disclosure',
            'http server header disclosure',
            'banner disclosure',
        ]
        
        for pattern in false_positive_patterns:
            if pattern in vuln_lower:
                if port_analysis.service in ['http', 'https'] and 'google' in str(port_analysis.banner).lower():
                    return False
                if port_analysis.service in ['http', 'https'] and port_analysis.port in [80, 443]:
                    return False
        
        significant_patterns = [
            'remote code execution',
            'buffer overflow',
            'authentication bypass',
            'privilege escalation',
            'sql injection',
            'cross-site scripting',
            'directory traversal',
            'command injection'
        ]
        
        for pattern in significant_patterns:
            if pattern in vuln_lower:
                return True
        
        return True
    
    def classify_vulnerability_severity(self, vulnerability: str, port_analysis: ComprehensivePortAnalysis) -> str:
        
        vuln_lower = vulnerability.lower()
        
        critical_patterns = [
            'remote code execution',
            'authentication bypass',
            'privilege escalation'
        ]
        
        high_patterns = [
            'buffer overflow',
            'sql injection',
            'command injection'
        ]
        
        medium_patterns = [
            'cross-site scripting',
            'directory traversal',
            'information disclosure'
        ]
        
        for pattern in critical_patterns:
            if pattern in vuln_lower:
                return 'critical'
        
        for pattern in high_patterns:
            if pattern in vuln_lower:
                return 'high'
        
        for pattern in medium_patterns:
            if pattern in vuln_lower:
                return 'medium'
        
        return 'low'
    
    def analyze_infrastructure_security(self, recon_data: Dict) -> Dict[str, Any]:
        
        analysis = {
            'cdn_protection': False,
            'cloud_security_features': False,
            'dns_security': False,
            'certificate_security': False,
            'infrastructure_score': 0
        }
        
        infrastructure = recon_data.get('infrastructure', {})
        cdn_detection = infrastructure.get('cdn_detection', {})
        if cdn_detection.get('detected', False):
            analysis['cdn_protection'] = True
            analysis['infrastructure_score'] += 20
        
        cloud_services = infrastructure.get('cloud_services', [])
        if cloud_services:
            analysis['cloud_security_features'] = True
            analysis['infrastructure_score'] += 15
        
        dns_data = recon_data.get('dns', {})
        dns_security = dns_data.get('dns_security', {})
        if dns_security.get('spf') or dns_security.get('dmarc'):
            analysis['dns_security'] = True
            analysis['infrastructure_score'] += 10
        
        cert_data = recon_data.get('certificates', {})
        if cert_data.get('certificates'):
            analysis['certificate_security'] = True
            analysis['infrastructure_score'] += 15
        
        return analysis
    
    def analyze_web_security(self, web_applications: List[WebApplicationDetails]) -> Dict[str, Any]:
        
        analysis = {
            'security_headers_score': 0,
            'cookie_security_score': 0,
            'overall_web_security': 0,
            'security_features': [],
            'security_issues': []
        }
        
        if not web_applications:
            return analysis
        
        web_app = web_applications[0] if web_applications else None
        if not web_app:
            return analysis
        
        security_headers = web_app.security_headers
        important_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options'
        ]
        
        present_headers = 0
        for header in important_headers:
            if any(header.lower() in h.lower() for h in security_headers.keys()):
                present_headers += 1
                analysis['security_features'].append(f'Security header: {header}')
        
        analysis['security_headers_score'] = (present_headers / len(important_headers)) * 100
        
        cookies_analysis = web_app.cookies_analysis
        if cookies_analysis:
            secure_cookies = cookies_analysis.get('secure_cookies', 0)
            total_cookies = cookies_analysis.get('total_cookies', 1)
            analysis['cookie_security_score'] = (secure_cookies / total_cookies) * 100
        
        analysis['overall_web_security'] = (
            analysis['security_headers_score'] * 0.7 + 
            analysis['cookie_security_score'] * 0.3
        )
        
        return analysis
    
    def generate_intelligent_recommendations(self, detailed_analysis: Dict, 
                                           network_host: NetworkHost) -> List[str]:
        
        recommendations = []
        
        service_analysis = detailed_analysis['service_security']
        if service_analysis['insecure_services'] > 0:
            recommendations.append(
                f"Secure {service_analysis['insecure_services']} unencrypted service(s) by implementing encryption"
            )
        
        if service_analysis['critical_services'] > 0:
            recommendations.append(
                "Replace critical insecure services (Telnet, FTP) with secure alternatives (SSH, SFTP)"
            )
        
        vuln_analysis = detailed_analysis['vulnerability_assessment']
        if vuln_analysis['critical_vulnerabilities'] > 0:
            recommendations.append(
                f"Immediately address {vuln_analysis['critical_vulnerabilities']} critical vulnerability/vulnerabilities"
            )
        
        if vuln_analysis['high_vulnerabilities'] > 0:
            recommendations.append(
                f"Address {vuln_analysis['high_vulnerabilities']} high-severity vulnerability/vulnerabilities"
            )
        
        encryption_analysis = detailed_analysis['encryption_analysis']
        if encryption_analysis['encryption_ratio'] < 0.5:
            recommendations.append(
                "Implement encryption for more services to improve security posture"
            )
        
        infra_analysis = detailed_analysis['infrastructure_security']
        if not infra_analysis['cdn_protection']:
            recommendations.append(
                "Consider implementing CDN protection for improved security and performance"
            )
        
        web_analysis = detailed_analysis['web_security']
        if web_analysis['security_headers_score'] < 70:
            recommendations.append(
                "Implement additional HTTP security headers (HSTS, CSP, X-Frame-Options)"
            )
        
        recommendations.extend([
            "Implement regular security monitoring and alerting",
            "Conduct regular security assessments and penetration testing",
            "Keep all services and software updated to latest versions",
            "Implement network segmentation to limit attack surface"
        ])
        
        return recommendations[:8]
    
    def assess_security_posture(self, overall_score: int, detailed_analysis: Dict) -> str:
        
        if overall_score >= 85:
            return "Excellent - Strong security posture with comprehensive protections"
        elif overall_score >= 75:
            return "Good - Solid security posture with minor areas for improvement"
        elif overall_score >= 60:
            return "Fair - Adequate security with several areas needing attention"
        elif overall_score >= 45:
            return "Poor - Significant security weaknesses that should be addressed"
        else:
            return "Critical - Major security issues requiring immediate attention"

class NetPulseEliteEngine:
    
    def __init__(self):
        self.reconnaissance = ComprehensiveReconnaissance()
        self.port_scanner = AdvancedPortScanner()
        self.security_assessor = IntelligentSecurityAssessment()
        
    async def analyze_target_comprehensive(self, target: str) -> Dict[str, Any]:
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Comprehensive Network Intelligence Analysis{Colors.END}")
        print(f"{Colors.BLUE}{'='*90}{Colors.END}")
        print(f"{Colors.YELLOW}Target: {target}{Colors.END}")
        print(f"{Colors.YELLOW}Analysis Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.YELLOW}Performing comprehensive analysis - all modules active{Colors.END}")
        print(f"{Colors.BLUE}{'='*90}{Colors.END}\n")
        
        results = {
            'metadata': {
                'target': target,
                'analysis_start': datetime.now().isoformat(),
                'analysis_type': 'comprehensive_intelligence',
                'modules_executed': []
            }
        }
        
        try:
            print(f"{Colors.BOLD}{Colors.GREEN}[PHASE 1] Intelligence Reconnaissance{Colors.END}")
            recon_data = await self.reconnaissance.gather_comprehensive_intelligence(target)
            results['reconnaissance'] = recon_data
            results['metadata']['modules_executed'].append('reconnaissance')
            
            print(f"\n{Colors.BOLD}{Colors.GREEN}[PHASE 2] Advanced Port Analysis{Colors.END}")
            port_analysis = await self.port_scanner.comprehensive_port_scan(target)
            results['port_analysis'] = [asdict(port) for port in port_analysis]
            results['metadata']['modules_executed'].append('port_scanning')
            
            print(f"\n{Colors.BOLD}{Colors.GREEN}[PHASE 3] Network Host Profiling{Colors.END}")
            network_host = await self.construct_network_host(target, recon_data, port_analysis)
            results['network_host'] = asdict(network_host)
            results['metadata']['modules_executed'].append('host_profiling')
            
            print(f"\n{Colors.BOLD}{Colors.GREEN}[PHASE 4] Intelligent Security Assessment{Colors.END}")
            security_assessment = self.security_assessor.assess_comprehensive_security(
                network_host, recon_data
            )
            results['security_assessment'] = security_assessment
            results['metadata']['modules_executed'].append('security_assessment')
            
            print(f"\n{Colors.BOLD}{Colors.GREEN}[PHASE 5] Generating Intelligence Report{Colors.END}")
            report = self.generate_comprehensive_report(results)
            results['comprehensive_report'] = report
            
            print(report)
            
            results['metadata']['analysis_end'] = datetime.now().isoformat()
            results['metadata']['analysis_duration'] = str(
                datetime.fromisoformat(results['metadata']['analysis_end']) - 
                datetime.fromisoformat(results['metadata']['analysis_start'])
            )
            
            return results
            
        except Exception as e:
            print(f"{Colors.RED}Analysis error: {e}{Colors.END}")
            results['error'] = str(e)
            return results
    
    async def construct_network_host(self, target: str, recon_data: Dict, 
                                   port_analysis: List[ComprehensivePortAnalysis]) -> NetworkHost:
        
        infrastructure_data = recon_data.get('infrastructure', {})
        asn_info = infrastructure_data.get('asn_info', {})
        geolocation_info = infrastructure_data.get('geolocation', {})
        
        first_ip = None
        if infrastructure_data.get('ip_addresses'):
            first_ip = infrastructure_data['ip_addresses'][0]
        
        network_info = NetworkInfrastructure(
            asn=asn_info.get(first_ip, {}).get('asn', 'Unknown') if first_ip else 'Unknown',
            organization=asn_info.get(first_ip, {}).get('organization', 'Unknown') if first_ip else 'Unknown',
            country=geolocation_info.get(first_ip, {}).get('country', 'Unknown') if first_ip else 'Unknown',
            city=geolocation_info.get(first_ip, {}).get('city', 'Unknown') if first_ip else 'Unknown',
            isp=asn_info.get(first_ip, {}).get('isp', 'Unknown') if first_ip else 'Unknown',
            hosting_provider='Unknown',
            cloud_service=' '.join(infrastructure_data.get('cloud_services', [])),
            cdn_provider=infrastructure_data.get('cdn_detection', {}).get('provider', 'None'),
            network_type='Public' if first_ip and not ipaddress.ip_address(first_ip).is_private else 'Unknown',
            estimated_users='Unknown'
        )
        
        threat_data = recon_data.get('threat_intel', {})
        threat_intel = ThreatIntelligence(
            ip_reputation=threat_data.get('reputation', 'Clean'),
            malware_domains=threat_data.get('malware_associations', []),
            threat_feeds=threat_data.get('threat_feeds', []),
            geolocation_risk='Low',
            known_vulnerabilities=[],
            security_headers=recon_data.get('web', {}).get('security_headers', {}),
            certificate_issues=[]
        )
        
        web_apps = []
        web_data = recon_data.get('web', {})
        if web_data:
            web_app = WebApplicationDetails(
                technologies=recon_data.get('technology', {}).get('frameworks', []),
                frameworks=recon_data.get('technology', {}).get('frameworks', []),
                cms_detection=recon_data.get('technology', {}).get('cms', 'Unknown'),
                javascript_libraries=recon_data.get('technology', {}).get('javascript_libraries', []),
                analytics_trackers=recon_data.get('technology', {}).get('analytics', []),
                advertising_networks=[],
                security_headers=web_data.get('security_headers', {}),
                cookies_analysis=web_data.get('cookies', {}),
                forms_detected=[],
                endpoints_discovered=[]
            )
            web_apps.append(web_app)
        
        network_host = NetworkHost(
            ip=first_ip or 'Unknown',
            hostname=target,
            fqdn=[target],
            operating_system='Unknown',
            device_type='Server',
            mac_address='Unknown',
            vendor='Unknown',
            network_info=network_info,
            threat_intel=threat_intel,
            open_ports=port_analysis,
            web_applications=web_apps,
            dns_records=recon_data.get('dns', {}).get('records', {}),
            ssl_certificates=recon_data.get('certificates', {}).get('certificates', []),
            network_path=[],
            response_times={},
            availability_score=100.0,
            security_posture='Unknown'
        )
        
        return network_host
    
    def generate_comprehensive_report(self, results: Dict[str, Any]) -> str:
        
        report_lines = []
        
        report_lines.extend([
            f"\n{Colors.BOLD}{Colors.BLUE}NETPULSE ELITE - COMPREHENSIVE NETWORK INTELLIGENCE REPORT{Colors.END}",
            f"{Colors.BLUE}{'='*90}{Colors.END}",
            f"Target: {results['metadata']['target']}",
            f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Analysis Duration: {results['metadata'].get('analysis_duration', 'Unknown')}",
            f"Modules Executed: {', '.join(results['metadata']['modules_executed'])}",
            f"{Colors.BLUE}{'='*90}{Colors.END}\n"
        ])
        
        security_assessment = results.get('security_assessment', {})
        overall_score = security_assessment.get('overall_score', 0)
        risk_level = security_assessment.get('risk_level', 'Unknown')
        security_posture = security_assessment.get('security_posture', 'Unknown')
        
        risk_colors = {
            'Low': Colors.GREEN,
            'Medium-Low': Colors.GREEN,
            'Medium': Colors.YELLOW,
            'Medium-High': Colors.YELLOW,
            'High': Colors.RED,
            'Critical': Colors.RED + Colors.BOLD
        }
        risk_color = risk_colors.get(risk_level, Colors.WHITE)
        
        report_lines.extend([
            f"{Colors.BOLD}EXECUTIVE SUMMARY{Colors.END}",
            f"Security Score: {Colors.CYAN}{overall_score}/100{Colors.END}",
            f"Risk Level: {risk_color}{risk_level}{Colors.END}",
            f"Security Posture: {security_posture}",
            ""
        ])
        
        network_host = results.get('network_host', {})
        network_info = network_host.get('network_info', {})
        
        report_lines.extend([
            f"{Colors.BOLD}NETWORK INTELLIGENCE OVERVIEW{Colors.END}",
            f"IP Address: {network_host.get('ip', 'Unknown')}",
            f"Organization: {network_info.get('organization', 'Unknown')}",
            f"ISP: {network_info.get('isp', 'Unknown')}",
            f"Country: {network_info.get('country', 'Unknown')}",
            f"City: {network_info.get('city', 'Unknown')}",
            f"ASN: {network_info.get('asn', 'Unknown')}",
            f"Cloud Service: {network_info.get('cloud_service', 'None')}",
            f"CDN Provider: {network_info.get('cdn_provider', 'None')}",
            ""
        ])
        
        port_analysis = results.get('port_analysis', [])
        if port_analysis:
            report_lines.extend([
                f"{Colors.BOLD}DISCOVERED SERVICES ANALYSIS{Colors.END}",
                f"Total Open Ports: {len(port_analysis)}"
            ])
            
            for port_data in port_analysis:
                port = port_data['port']
                service = port_data['service']
                version = port_data['version']
                state = port_data['state']
                
                security = port_data.get('security_assessment', {})
                risk_level_port = security.get('risk_level', 'Unknown')
                encryption = security.get('encryption_status', 'Unknown')
                
                state_color = Colors.GREEN if state == 'open' else Colors.YELLOW
                risk_color = {'Low': Colors.GREEN, 'Medium': Colors.YELLOW, 'High': Colors.RED, 'Critical': Colors.RED}.get(risk_level_port, Colors.WHITE)
                
                report_lines.append(
                    f"  Port {port:5d}: {state_color}{state.upper():<8}{Colors.END} "
                    f"{service:<15} {version:<20} "
                    f"Risk: {risk_color}{risk_level_port:<8}{Colors.END} "
                    f"Encryption: {encryption}"
                )
                
                vulnerabilities = security.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    report_lines.append(f"    {Colors.RED}⚠ {vuln}{Colors.END}")
            
            report_lines.append("")
        
        dns_data = results.get('reconnaissance', {}).get('dns', {})
        if dns_data.get('records'):
            report_lines.extend([
                f"{Colors.BOLD}DNS INTELLIGENCE{Colors.END}",
                f"A Records: {', '.join(dns_data['records'].get('A', []))[:100]}",
                f"MX Records: {', '.join(dns_data['records'].get('MX', []))[:100]}",
                f"NS Records: {', '.join(dns_data['records'].get('NS', []))[:100]}",
                f"TXT Records: {len(dns_data['records'].get('TXT', []))} found",
                ""
            ])
        
        tech_data = results.get('reconnaissance', {}).get('technology', {})
        if tech_data:
            report_lines.extend([
                f"{Colors.BOLD}TECHNOLOGY STACK INTELLIGENCE{Colors.END}",
                f"Web Server: {tech_data.get('web_server', 'Unknown')}",
                f"CMS: {tech_data.get('cms', 'Unknown')}",
                f"Frameworks: {', '.join(tech_data.get('frameworks', []))}",
                f"JavaScript Libraries: {', '.join(tech_data.get('javascript_libraries', []))}",
                f"Analytics: {', '.join(tech_data.get('analytics', []))}",
                ""
            ])
        
        detailed_analysis = security_assessment.get('detailed_analysis', {})
        if detailed_analysis:
            report_lines.extend([
                f"{Colors.BOLD}DETAILED SECURITY ANALYSIS{Colors.END}",
            ])
            
            service_security = detailed_analysis.get('service_security', {})
            report_lines.extend([
                f"Service Security:",
                f"  Secure Services: {service_security.get('secure_services', 0)}",
                f"  Insecure Services: {service_security.get('insecure_services', 0)}",
                f"  Critical Services: {service_security.get('critical_services', 0)}",
            ])
            
            vuln_assessment = detailed_analysis.get('vulnerability_assessment', {})
            report_lines.extend([
                f"Vulnerability Assessment:",
                f"  Critical Vulnerabilities: {Colors.RED}{vuln_assessment.get('critical_vulnerabilities', 0)}{Colors.END}",
                f"  High Vulnerabilities: {Colors.YELLOW}{vuln_assessment.get('high_vulnerabilities', 0)}{Colors.END}",
                f"  Medium Vulnerabilities: {vuln_assessment.get('medium_vulnerabilities', 0)}",
                f"  Low Vulnerabilities: {vuln_assessment.get('low_vulnerabilities', 0)}",
                f"  False Positives Filtered: {vuln_assessment.get('false_positives_filtered', 0)}",
            ])
            
            infra_security = detailed_analysis.get('infrastructure_security', {})
            report_lines.extend([
                f"Infrastructure Security:",
                f"  CDN Protection: {'Yes' if infra_security.get('cdn_protection') else 'No'}",
                f"  Cloud Security Features: {'Yes' if infra_security.get('cloud_security_features') else 'No'}",
                f"  DNS Security: {'Yes' if infra_security.get('dns_security') else 'No'}",
                f"  Certificate Security: {'Yes' if infra_security.get('certificate_security') else 'No'}",
                f"  Infrastructure Score: {infra_security.get('infrastructure_score', 0)}/100",
            ])
            
            web_security = detailed_analysis.get('web_security', {})
            if web_security:
                report_lines.extend([
                    f"Web Application Security:",
                    f"  Security Headers Score: {web_security.get('security_headers_score', 0):.1f}/100",
                    f"  Cookie Security Score: {web_security.get('cookie_security_score', 0):.1f}/100",
                    f"  Overall Web Security: {web_security.get('overall_web_security', 0):.1f}/100",
                ])
            
            report_lines.append("")
        
        threat_intel = network_host.get('threat_intel', {})
        if threat_intel:
            reputation = threat_intel.get('ip_reputation', 'Unknown')
            reputation_color = Colors.GREEN if reputation == 'Clean' else Colors.RED
            
            report_lines.extend([
                f"{Colors.BOLD}THREAT INTELLIGENCE{Colors.END}",
                f"IP Reputation: {reputation_color}{reputation}{Colors.END}",
                f"Malware Associations: {len(threat_intel.get('malware_domains', []))} found",
                f"Threat Feeds: {len(threat_intel.get('threat_feeds', []))} sources",
                f"Geolocation Risk: {threat_intel.get('geolocation_risk', 'Unknown')}",
                ""
            ])
        
        subdomain_data = results.get('reconnaissance', {}).get('subdomains', {})
        if subdomain_data.get('discovered'):
            report_lines.extend([
                f"{Colors.BOLD}SUBDOMAIN INTELLIGENCE{Colors.END}",
                f"Subdomains Discovered: {len(subdomain_data['discovered'])}",
                f"Active Subdomains: {len(subdomain_data.get('active', []))}",
            ])
            
            for subdomain in subdomain_data['discovered'][:10]:
                domain = subdomain.get('domain', 'Unknown')
                ip = subdomain.get('ip', 'Unknown')
                is_active = domain in subdomain_data.get('active', [])
                status_color = Colors.GREEN if is_active else Colors.YELLOW
                status = 'Active' if is_active else 'Inactive'
                
                report_lines.append(f"  {domain:<30} {ip:<15} {status_color}{status}{Colors.END}")
            
            if len(subdomain_data['discovered']) > 10:
                report_lines.append(f"  ... and {len(subdomain_data['discovered']) - 10} more subdomains")
            
            report_lines.append("")
        
        web_apps = network_host.get('web_applications', [])
        if web_apps:
            web_app = web_apps[0]
            report_lines.extend([
                f"{Colors.BOLD}WEB APPLICATION ANALYSIS{Colors.END}",
                f"Detected Technologies: {', '.join(web_app.get('technologies', []))}",
                f"Frameworks: {', '.join(web_app.get('frameworks', []))}",
                f"CMS: {web_app.get('cms_detection', 'None')}",
                f"JavaScript Libraries: {', '.join(web_app.get('javascript_libraries', []))}",
                f"Analytics Trackers: {', '.join(web_app.get('analytics_trackers', []))}",
                ""
            ])
            
            security_headers = web_app.get('security_headers', {})
            if security_headers:
                report_lines.extend([
                    f"Security Headers Analysis:",
                    f"  Present: {len(security_headers.get('present', []))} important headers",
                    f"  Missing: {len(security_headers.get('missing', []))} important headers",
                ])
                
                for missing in security_headers.get('missing', [])[:5]:
                    header_name = missing.get('header', 'Unknown')
                    risk = missing.get('risk', 'Unknown')
                    report_lines.append(f"    {Colors.YELLOW}⚠ Missing: {header_name} - {risk}{Colors.END}")
                
                report_lines.append("")
        
        social_data = results.get('reconnaissance', {}).get('social', {})
        if social_data.get('platforms'):
            report_lines.extend([
                f"{Colors.BOLD}DIGITAL FOOTPRINT ANALYSIS{Colors.END}",
                f"Social Media Presence: {', '.join(social_data['platforms'])}",
                f"External Links Found: {len(social_data.get('links_found', []))}",
                ""
            ])
        
        email_data = results.get('reconnaissance', {}).get('emails', {})
        if email_data.get('addresses'):
            report_lines.extend([
                f"{Colors.BOLD}EMAIL INTELLIGENCE{Colors.END}",
                f"Email Addresses Found: {len(email_data['addresses'])}",
                f"Email Patterns: {email_data.get('patterns', {})}",
                ""
            ])
        
        recommendations = security_assessment.get('recommendations', [])
        if recommendations:
            report_lines.extend([
                f"{Colors.BOLD}SECURITY RECOMMENDATIONS{Colors.END}",
            ])
            
            for i, recommendation in enumerate(recommendations, 1):
                report_lines.append(f"{i:2d}. {recommendation}")
            
            report_lines.append("")
        
        report_lines.extend([
            f"{Colors.BOLD}RISK ASSESSMENT SUMMARY{Colors.END}",
            f"Overall Security Score: {Colors.CYAN}{overall_score}/100{Colors.END}",
            f"Risk Level: {risk_color}{risk_level}{Colors.END}",
            f"Primary Risk Factors:",
        ])
        
        risk_factors = []
        
        if detailed_analysis:
            service_security = detailed_analysis.get('service_security', {})
            if service_security.get('critical_services', 0) > 0:
                risk_factors.append(f"Critical insecure services detected")
            
            vuln_assessment = detailed_analysis.get('vulnerability_assessment', {})
            if vuln_assessment.get('critical_vulnerabilities', 0) > 0:
                risk_factors.append(f"Critical vulnerabilities present")
            
            encryption_analysis = detailed_analysis.get('encryption_analysis', {})
            if encryption_analysis.get('encryption_ratio', 1.0) < 0.5:
                risk_factors.append(f"Low encryption adoption rate")
            
            infra_security = detailed_analysis.get('infrastructure_security', {})
            if not infra_security.get('cdn_protection', True):
                risk_factors.append(f"No CDN protection detected")
        
        if not risk_factors:
            risk_factors.append("No significant risk factors identified")
        
        for factor in risk_factors:
            report_lines.append(f"  • {factor}")
        
        report_lines.extend([
            "",
            f"{Colors.BOLD}COMPLIANCE CONSIDERATIONS{Colors.END}",
            f"Industry Standards:",
            f"  • SSL/TLS Implementation: {'✓' if any('https' in str(p) for p in port_analysis) else '✗'}",
            f"  • Secure Service Protocols: {'✓' if detailed_analysis.get('encryption_analysis', {}).get('encryption_ratio', 0) > 0.5 else '✗'}",
            f"  • Security Headers: {'✓' if detailed_analysis.get('web_security', {}).get('security_headers_score', 0) > 70 else '✗'}",
            f"  • DNS Security: {'✓' if detailed_analysis.get('infrastructure_security', {}).get('dns_security') else '✗'}",
            ""
        ])
        
        report_lines.extend([
            f"{Colors.BLUE}{'='*90}{Colors.END}",
            f"Analysis completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Report generated by NetPulse Elite v2.0",
            f"For detailed technical analysis, review individual module outputs",
            f"{Colors.BLUE}{'='*90}{Colors.END}\n"
        ])
        
        return '\n'.join(report_lines)

class ContinuousNetworkDatabase:
    
    def __init__(self, db_path: str = "netpulse_continuous.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                results_json TEXT NOT NULL,
                security_score INTEGER,
                risk_level TEXT,
                alerts_generated INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE NOT NULL,
                baseline_data BLOB NOT NULL,
                created_timestamp TEXT NOT NULL,
                updated_timestamp TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0,
                resolved INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                change_type TEXT NOT NULL,
                before_state_json TEXT NOT NULL,
                after_state_json TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                impact_assessment TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                interface TEXT NOT NULL,
                analysis_data BLOB NOT NULL,
                anomaly_count INTEGER DEFAULT 0,
                threat_count INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                metric_unit TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_analysis_result(self, target: str, analysis_type: str, results: Dict) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        security_score = results.get('security_assessment', {}).get('overall_score', 0)
        risk_level = results.get('security_assessment', {}).get('risk_level', 'Unknown')
        
        cursor.execute('''
            INSERT INTO analysis_history 
            (timestamp, target, analysis_type, results_json, security_score, risk_level)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            target,
            analysis_type,
            json.dumps(results, default=str),
            security_score,
            risk_level
        ))
        
        conn.commit()
        conn.close()
    
    def get_analysis_history(self, target: str, limit: int = 100) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, analysis_type, security_score, risk_level
            FROM analysis_history 
            WHERE target = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (target, limit))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'timestamp': row[0],
                'analysis_type': row[1],
                'security_score': row[2],
                'risk_level': row[3]
            })
        
        conn.close()
        return results
    
    def store_baseline(self, target: str, baseline: NetworkBaseline) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        baseline_data = pickle.dumps(baseline)
        timestamp = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO network_baselines 
            (target, baseline_data, created_timestamp, updated_timestamp)
            VALUES (?, ?, ?, ?)
        ''', (target, baseline_data, timestamp, timestamp))
        
        conn.commit()
        conn.close()
    
    def get_baseline(self, target: str) -> Optional[NetworkBaseline]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT baseline_data FROM network_baselines WHERE target = ?
        ''', (target,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return pickle.loads(result[0])
        return None
    
    def store_alert(self, alert: ContinuousAlert) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO alerts 
            (alert_id, timestamp, target, severity, category, title, description, evidence_json, acknowledged, resolved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.alert_id,
            alert.timestamp.isoformat(),
            alert.target,
            alert.severity,
            alert.category,
            alert.title,
            alert.description,
            json.dumps(alert.evidence, default=str),
            alert.acknowledged,
            alert.resolved
        ))
        
        conn.commit()
        conn.close()
    
    def get_active_alerts(self, target: str = None) -> List[ContinuousAlert]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if target:
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE target = ? AND resolved = 0
                ORDER BY timestamp DESC
            ''', (target,))
        else:
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE resolved = 0
                ORDER BY timestamp DESC
            ''')
        
        alerts = []
        for row in cursor.fetchall():
            alert = ContinuousAlert(
                alert_id=row[1],
                timestamp=datetime.fromisoformat(row[2]),
                target=row[3],
                severity=row[4],
                category=row[5],
                title=row[6],
                description=row[7],
                evidence=json.loads(row[8]),
                recommended_actions=[],
                acknowledged=bool(row[9]),
                resolved=bool(row[10])
            )
            alerts.append(alert)
        
        conn.close()
        return alerts

class RealTimeTrafficAnalyzer:
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.packet_queue = asyncio.Queue(maxsize=50000)
        self.analysis_results = deque(maxlen=1000)
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.protocol_stats = defaultdict(int)
        self.flow_tracker = defaultdict(list)
        self.threat_signatures = self.load_threat_signatures()
        self.running = False
        
    def load_threat_signatures(self) -> Dict[str, List[str]]:
        return {
            'malware_domains': [
                'malware.example.com', 'botnet.evil.com', 'phishing.bad.com'
            ],
            'suspicious_ports': [4444, 5555, 6666, 31337, 12345],
            'attack_patterns': [
                b'../../../../etc/passwd',
                b'<script>alert(',
                b'SELECT * FROM users',
                b'\x90\x90\x90\x90'
            ],
            'anomalous_user_agents': [
                'sqlmap', 'nmap', 'masscan', 'zmap', 'nikto'
            ]
        }
    
    async def start_continuous_capture(self):
        print(f"{Colors.CYAN}🌐 Starting continuous traffic analysis...{Colors.END}")
        
        self.running = True
        
        tasks = [
            asyncio.create_task(self.packet_capture_loop()),
            asyncio.create_task(self.traffic_analysis_loop()),
            asyncio.create_task(self.anomaly_detection_loop()),
            asyncio.create_task(self.threat_detection_loop()),
            asyncio.create_task(self.performance_monitoring_loop())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Stopping traffic analysis...{Colors.END}")
            self.running = False
            for task in tasks:
                task.cancel()
    
    async def packet_capture_loop(self):
        def packet_handler(packet):
            try:
                if not self.packet_queue.full():
                    self.packet_queue.put_nowait(packet)
            except:
                pass
        
        try:
            scapy.sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"{Colors.RED}Packet capture error: {e}{Colors.END}")
    
    async def traffic_analysis_loop(self):
        analysis_window = []
        
        while self.running:
            try:
                for _ in range(100):
                    try:
                        packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                        analysis_window.append(packet)
                    except asyncio.TimeoutError:
                        break
                
                if analysis_window:
                    analysis_result = self.analyze_traffic_window(analysis_window)
                    self.analysis_results.append(analysis_result)
                    
                    self.display_traffic_stats(analysis_result)
                    
                    analysis_window.clear()
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"Traffic analysis error: {e}")
                await asyncio.sleep(1)
    
    def analyze_traffic_window(self, packets: List[scapy.Packet]) -> TrafficAnalysisResult:
        protocol_dist = defaultdict(int)
        talkers = defaultdict(int)
        anomalous_traffic = []
        threat_indicators = []
        
        for packet in packets:
            if packet.haslayer(TCP):
                protocol_dist['TCP'] += 1
            elif packet.haslayer(UDP):
                protocol_dist['UDP'] += 1
            elif packet.haslayer(ICMP):
                protocol_dist['ICMP'] += 1
            else:
                protocol_dist['OTHER'] += 1
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                talkers[src_ip] += len(packet)
            
            threats = self.detect_packet_threats(packet)
            threat_indicators.extend(threats)
            
            if self.is_anomalous_packet(packet):
                anomalous_traffic.append({
                    'timestamp': time.time(),
                    'src': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                    'dst': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                    'reason': 'Statistical anomaly detected'
                })
        
        top_talkers = sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return TrafficAnalysisResult(
            timestamp=datetime.now(),
            interface=self.interface or 'default',
            protocol_distribution=dict(protocol_dist),
            top_talkers=top_talkers,
            anomalous_traffic=anomalous_traffic,
            threat_indicators=list(set(threat_indicators)),
            performance_metrics=self.calculate_performance_metrics(packets),
            bandwidth_utilization=self.calculate_bandwidth_utilization(packets)
        )
    
    def detect_packet_threats(self, packet: scapy.Packet) -> List[str]:
        threats = []
        
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                if dst_port in self.threat_signatures['suspicious_ports']:
                    threats.append(f"Suspicious port activity: {dst_port}")
            
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw])
                for pattern in self.threat_signatures['attack_patterns']:
                    if pattern in payload:
                        threats.append(f"Attack pattern detected: {pattern[:20]}")
        
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            qname = packet[DNS].qd.qname.decode().lower()
            for malware_domain in self.threat_signatures['malware_domains']:
                if malware_domain in qname:
                    threats.append(f"DNS query to malicious domain: {qname}")
        
        return threats
    
    def is_anomalous_packet(self, packet: scapy.Packet) -> bool:
        if len(packet) > 9000:
            return True
        
        if packet.haslayer(IP):
            if packet.haslayer(TCP) and packet.haslayer(UDP):
                return True
            
            if packet.haslayer(TCP) and packet[TCP].flags == 2:
                dst_port = packet[TCP].dport
                if dst_port > 50000:
                    return True
        
        return False
    
    def calculate_performance_metrics(self, packets: List[scapy.Packet]) -> Dict[str, float]:
        if not packets:
            return {}
        
        packet_sizes = [len(packet) for packet in packets]
        
        return {
            'avg_packet_size': statistics.mean(packet_sizes),
            'max_packet_size': max(packet_sizes),
            'min_packet_size': min(packet_sizes),
            'packet_rate': len(packets),
            'total_bytes': sum(packet_sizes)
        }
    
    def calculate_bandwidth_utilization(self, packets: List[scapy.Packet]) -> float:
        if not packets:
            return 0.0
        
        total_bytes = sum(len(packet) for packet in packets)
        interface_capacity = 1_000_000_000 / 8
        
        utilization = (total_bytes / interface_capacity) * 100
        return min(utilization, 100.0)
    
    def display_traffic_stats(self, result: TrafficAnalysisResult):
        print(f"\r{Colors.CYAN}📊 Traffic Analysis - "
              f"Packets: {sum(result.protocol_distribution.values())} | "
              f"Bandwidth: {result.bandwidth_utilization:.1f}% | "
              f"Threats: {len(result.threat_indicators)} | "
              f"Anomalies: {len(result.anomalous_traffic)}{Colors.END}", end='', flush=True)
        
        if len(result.threat_indicators) > 5:
            print(f"\n{Colors.RED}🚨 HIGH THREAT ACTIVITY DETECTED: {len(result.threat_indicators)} indicators{Colors.END}")
        
        if result.bandwidth_utilization > 80:
            print(f"\n{Colors.YELLOW}⚠️ HIGH BANDWIDTH UTILIZATION: {result.bandwidth_utilization:.1f}%{Colors.END}")
    
    async def anomaly_detection_loop(self):
        feature_buffer = deque(maxlen=1000)
        
        while self.running:
            try:
                await asyncio.sleep(30)
                
                if len(self.analysis_results) < 10:
                    continue
                
                features = []
                for result in list(self.analysis_results)[-50:]:
                    feature_vector = [
                        sum(result.protocol_distribution.values()),
                        result.bandwidth_utilization,
                        len(result.threat_indicators),
                        len(result.anomalous_traffic),
                        result.performance_metrics.get('avg_packet_size', 0)
                    ]
                    features.append(feature_vector)
                
                if len(features) >= 20:
                    features_array = np.array(features)
                    anomalies = self.anomaly_detector.fit_predict(features_array)
                    
                    anomaly_count = np.sum(anomalies == -1)
                    if anomaly_count > 0:
                        print(f"\n{Colors.YELLOW}🔍 ML Anomaly Detection: {anomaly_count} anomalous periods detected{Colors.END}")
                        
            except Exception as e:
                print(f"Anomaly detection error: {e}")
    
    async def threat_detection_loop(self):
        while self.running:
            try:
                await asyncio.sleep(60)
                
                if not self.analysis_results:
                    continue
                
                recent_results = list(self.analysis_results)[-10:]
                
                all_threats = []
                for result in recent_results:
                    all_threats.extend(result.threat_indicators)
                
                if all_threats:
                    threat_summary = defaultdict(int)
                    for threat in all_threats:
                        threat_type = threat.split(':')[0]
                        threat_summary[threat_type] += 1
                    
                    print(f"\n{Colors.RED}🚨 Threat Summary (Last 10 minutes):{Colors.END}")
                    for threat_type, count in threat_summary.items():
                        print(f"  • {threat_type}: {count} occurrences")
                        
            except Exception as e:
                print(f"Threat detection error: {e}")
    
    async def performance_monitoring_loop(self):
        while self.running:
            try:
                await asyncio.sleep(300)
                
                if len(self.analysis_results) < 5:
                    continue
                
                recent_results = list(self.analysis_results)[-10:]
                
                bandwidth_trend = [r.bandwidth_utilization for r in recent_results]
                packet_rate_trend = [sum(r.protocol_distribution.values()) for r in recent_results]
                
                avg_bandwidth = statistics.mean(bandwidth_trend)
                avg_packet_rate = statistics.mean(packet_rate_trend)
                
                print(f"\n{Colors.BLUE}📈 Performance Metrics (5-minute average):{Colors.END}")
                print(f"  Bandwidth Utilization: {avg_bandwidth:.1f}%")
                print(f"  Packet Rate: {avg_packet_rate:.0f} packets/window")
                print(f"  Active Flows: {len(self.flow_tracker)}")
                
                if avg_bandwidth > 90:
                    print(f"  {Colors.RED}⚠️ CRITICAL: High bandwidth utilization{Colors.END}")
                elif avg_bandwidth > 70:
                    print(f"  {Colors.YELLOW}⚠️ WARNING: Elevated bandwidth utilization{Colors.END}")
                    
            except Exception as e:
                print(f"Performance monitoring error: {e}")

class ContinuousMonitoringEngine:
    
    def __init__(self, db: ContinuousNetworkDatabase):
        self.db = db
        self.targets = {}
        self.monitoring_tasks = {}
        self.alert_handlers = []
        self.change_detection_enabled = True
        self.baseline_learning_period = timedelta(hours=24)
        
    def add_target(self, target: str, monitoring_config: Dict = None):
        if monitoring_config is None:
            monitoring_config = {
                'interval': 300,
                'alert_thresholds': {
                    'security_score_drop': 10,
                    'new_services': True,
                    'service_changes': True,
                    'certificate_changes': True,
                    'performance_degradation': 50
                },
                'baseline_update_interval': timedelta(days=7)
            }
        
        self.targets[target] = monitoring_config
        print(f"{Colors.GREEN}✓ Added {target} to continuous monitoring{Colors.END}")
    
    def add_alert_handler(self, handler: Callable):
        self.alert_handlers.append(handler)
    
    async def start_monitoring(self):
        print(f"{Colors.CYAN}🔄 Starting continuous monitoring for {len(self.targets)} targets...{Colors.END}")
        
        for target in self.targets:
            task = asyncio.create_task(self.monitor_target_continuously(target))
            self.monitoring_tasks[target] = task
        
        alert_task = asyncio.create_task(self.process_alerts_continuously())
        
        try:
            await asyncio.gather(*self.monitoring_tasks.values(), alert_task)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Stopping continuous monitoring...{Colors.END}")
            for task in self.monitoring_tasks.values():
                task.cancel()
            alert_task.cancel()
    
    async def monitor_target_continuously(self, target: str):
        config = self.targets[target]
        interval = config['interval']
        
        baseline = self.db.get_baseline(target)
        if not baseline:
            print(f"{Colors.YELLOW}📊 Creating baseline for {target}...{Colors.END}")
            baseline = await self.create_baseline(target)
            self.db.store_baseline(target, baseline)
        
        print(f"{Colors.BLUE}🔍 Monitoring {target} every {interval} seconds{Colors.END}")
        
        while True:
            try:
                engine = NetPulseEliteEngine()
                current_analysis = await engine.analyze_target_comprehensive(target)
                
                self.db.store_analysis_result(target, 'continuous_monitoring', current_analysis)
                
                alerts = await self.compare_with_baseline(target, baseline, current_analysis)
                
                for alert in alerts:
                    self.db.store_alert(alert)
                    await self.handle_alert(alert)
                
                if self.should_update_baseline(baseline, config):
                    print(f"{Colors.CYAN}📊 Updating baseline for {target}...{Colors.END}")
                    baseline = await self.update_baseline(target, baseline, current_analysis)
                    self.db.store_baseline(target, baseline)
                
                self.display_monitoring_status(target, current_analysis, alerts)
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                print(f"{Colors.RED}Monitoring error for {target}: {e}{Colors.END}")
                await asyncio.sleep(60)
    
    async def create_baseline(self, target: str) -> NetworkBaseline:
        engine = NetPulseEliteEngine()
        
        analysis = await engine.analyze_target_comprehensive(target)
        
        network_host = analysis.get('network_host', {})
        port_analysis = analysis.get('port_analysis', [])
        
        normal_services = [port['port'] for port in port_analysis if port['state'] == 'open']
        normal_response_times = {
            port['port']: port.get('performance_metrics', {}).get('connection_time_ms', 0)
            for port in port_analysis if port['state'] == 'open'
        }
        
        dns_records = analysis.get('reconnaissance', {}).get('dns', {}).get('records', {})
        ssl_certs = analysis.get('reconnaissance', {}).get('certificates', {})
        
        baseline = NetworkBaseline(
            target=target,
            baseline_timestamp=datetime.now(),
            normal_services=normal_services,
            normal_response_times=normal_response_times,
            normal_ssl_config=ssl_certs,
            normal_dns_records=dns_records,
            traffic_patterns={},
            performance_metrics={
                'avg_response_time': statistics.mean(normal_response_times.values()) if normal_response_times else 0,
                'service_count': len(normal_services)
            },
            security_posture=analysis.get('security_assessment', {})
        )
        
        return baseline
    
    async def compare_with_baseline(self, target: str, baseline: NetworkBaseline, 
                                 current_analysis: Dict) -> List[ContinuousAlert]:
        alerts = []
        config = self.targets[target]
        thresholds = config['alert_thresholds']
        
        current_ports = [port['port'] for port in current_analysis.get('port_analysis', []) 
                        if port['state'] == 'open']
        current_security = current_analysis.get('security_assessment', {})
        
        new_services = set(current_ports) - set(baseline.normal_services)
        removed_services = set(baseline.normal_services) - set(current_ports)
        
        if new_services and thresholds.get('new_services', True):
            alert = ContinuousAlert(
                alert_id=f"new_services_{target}_{int(time.time())}",
                timestamp=datetime.now(),
                severity='medium',
                category='service_change',
                target=target,
                title=f"New services detected on {target}",
                description=f"New services found: {', '.join(map(str, new_services))}",
                evidence={'new_services': list(new_services), 'baseline_services': baseline.normal_services},
                recommended_actions=[
                    "Verify if new services are authorized",
                    "Review service configurations",
                    "Update security policies if needed"
                ]
            )
            alerts.append(alert)
        
        if removed_services:
            alert = ContinuousAlert(
                alert_id=f"removed_services_{target}_{int(time.time())}",
                timestamp=datetime.now(),
                severity='low',
                category='service_change',
                target=target,
                title=f"Services removed from {target}",
                description=f"Services no longer available: {', '.join(map(str, removed_services))}",
                evidence={'removed_services': list(removed_services)},
                recommended_actions=[
                    "Verify if service removal was planned",
                    "Check for potential service outages"
                ]
            )
            alerts.append(alert)
        
        baseline_score = baseline.security_posture.get('overall_score', 0)
        current_score = current_security.get('overall_score', 0)
        score_drop = baseline_score - current_score
        
        if score_drop >= thresholds.get('security_score_drop', 10):
            alert = ContinuousAlert(
                alert_id=f"security_degradation_{target}_{int(time.time())}",
                timestamp=datetime.now(),
                severity='high' if score_drop >= 20 else 'medium',
                category='security_issue',
                target=target,
                title=f"Security score degradation for {target}",
                description=f"Security score dropped by {score_drop} points (from {baseline_score} to {current_score})",
                evidence={
                    'baseline_score': baseline_score,
                    'current_score': current_score,
                    'score_drop': score_drop
                },
                recommended_actions=[
                    "Investigate security configuration changes",
                    "Review recent vulnerabilities",
                    "Check for service misconfigurations"
                ]
            )
            alerts.append(alert)
        
        current_response_times = {
            port['port']: port.get('performance_metrics', {}).get('connection_time_ms', 0)
            for port in current_analysis.get('port_analysis', []) if port['state'] == 'open'
        }
        
        for port in baseline.normal_response_times:
            if port in current_response_times:
                baseline_time = baseline.normal_response_times[port]
                current_time = current_response_times[port]
                
                if baseline_time > 0:
                    degradation_pct = ((current_time - baseline_time) / baseline_time) * 100
                    
                    if degradation_pct >= thresholds.get('performance_degradation', 50):
                        alert = ContinuousAlert(
                            alert_id=f"performance_degradation_{target}_{port}_{int(time.time())}",
                            timestamp=datetime.now(),
                            severity='medium',
                            category='performance_degradation',
                            target=target,
                            title=f"Performance degradation on {target}:{port}",
                            description=f"Response time increased by {degradation_pct:.1f}% (from {baseline_time:.1f}ms to {current_time:.1f}ms)",
                            evidence={
                                'port': port,
                                'baseline_time': baseline_time,
                                'current_time': current_time,
                                'degradation_percent': degradation_pct
                            },
                            recommended_actions=[
                                "Check network connectivity",
                                "Review server performance",
                                "Investigate potential congestion"
                            ]
                        )
                        alerts.append(alert)
        
        baseline_certs = baseline.normal_ssl_config.get('certificates', [])
        current_certs = current_analysis.get('reconnaissance', {}).get('certificates', {}).get('certificates', [])
        
        if baseline_certs and current_certs:
            baseline_cert_hash = hashlib.md5(str(baseline_certs).encode()).hexdigest()
            current_cert_hash = hashlib.md5(str(current_certs).encode()).hexdigest()
            
            if baseline_cert_hash != current_cert_hash and thresholds.get('certificate_changes', True):
                alert = ContinuousAlert(
                    alert_id=f"certificate_change_{target}_{int(time.time())}",
                    timestamp=datetime.now(),
                    severity='medium',
                    category='certificate_change',
                    target=target,
                    title=f"SSL certificate change detected for {target}",
                    description="SSL certificate configuration has changed",
                    evidence={
                        'baseline_cert_count': len(baseline_certs),
                        'current_cert_count': len(current_certs)
                    },
                    recommended_actions=[
                        "Verify certificate renewal was planned",
                        "Check certificate validity",
                        "Update certificate monitoring"
                    ]
                )
                alerts.append(alert)
        
        return alerts
    
    def should_update_baseline(self, baseline: NetworkBaseline, config: Dict) -> bool:
        update_interval = config.get('baseline_update_interval', timedelta(days=7))
        time_since_baseline = datetime.now() - baseline.baseline_timestamp
        
        return time_since_baseline >= update_interval
    
    async def update_baseline(self, target: str, old_baseline: NetworkBaseline, 
                           current_analysis: Dict) -> NetworkBaseline:
        new_baseline = await self.create_baseline(target)
        
        new_baseline.baseline_timestamp = datetime.now()
        
        return new_baseline
    
    async def handle_alert(self, alert: ContinuousAlert):
        severity_colors = {
            'critical': Colors.RED + Colors.BOLD,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.BLUE,
            'info': Colors.CYAN
        }
        
        color = severity_colors.get(alert.severity, Colors.WHITE)
        
        print(f"\n{color}🚨 ALERT [{alert.severity.upper()}] - {alert.title}{Colors.END}")
        print(f"   Target: {alert.target}")
        print(f"   Category: {alert.category}")
        print(f"   Description: {alert.description}")
        print(f"   Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                print(f"Alert handler error: {e}")
    
    def display_monitoring_status(self, target: str, analysis: Dict, alerts: List[ContinuousAlert]):
        security_score = analysis.get('security_assessment', {}).get('overall_score', 0)
        risk_level = analysis.get('security_assessment', {}).get('risk_level', 'Unknown')
        open_ports = len(analysis.get('port_analysis', []))
        
        status_line = (f"{Colors.BLUE}📊 {target}: "
                      f"Score={security_score}/100, Risk={risk_level}, "
                      f"Ports={open_ports}, Alerts={len(alerts)}{Colors.END}")
        
        print(f"\r{status_line}", end='', flush=True)
        
        if alerts:
            print(f"\n{Colors.YELLOW}   New alerts generated: {len(alerts)}{Colors.END}")
    
    async def process_alerts_continuously(self):
        while True:
            try:
                await asyncio.sleep(60)
                
                active_alerts = self.db.get_active_alerts()
                
                if active_alerts:
                    alert_summary = defaultdict(int)
                    for alert in active_alerts:
                        alert_summary[alert.severity] += 1
                    
                    if int(time.time()) % 300 == 0:
                        print(f"\n{Colors.CYAN}📋 Active Alerts Summary:{Colors.END}")
                        for severity, count in alert_summary.items():
                            color = {'critical': Colors.RED, 'high': Colors.RED, 
                                   'medium': Colors.YELLOW, 'low': Colors.BLUE}.get(severity, Colors.WHITE)
                            print(f"   {color}{severity.capitalize()}: {count}{Colors.END}")
                
            except Exception as e:
                print(f"Alert processing error: {e}")

class NotificationSystem:
    
    def __init__(self, config_file: str = 'netpulse_notifications.conf'):
        self.config = configparser.ConfigParser()
        self.config_file = config_file
        self.load_config()
        
    def load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.config['EMAIL'] = {
                'enabled': 'false',
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': '587',
                'username': '',
                'password': '',
                'recipients': ''
            }
            
            self.config['SLACK'] = {
                'enabled': 'false',
                'webhook_url': '',
                'channel': '#alerts'
            }
            
            self.config['DISCORD'] = {
                'enabled': 'false',
                'webhook_url': ''
            }
            
            with open(self.config_file, 'w') as f:
                self.config.write(f)
    
    async def send_alert_notification(self, alert: ContinuousAlert):
        try:
            if self.config.getboolean('EMAIL', 'enabled', fallback=False):
                await self.send_email_alert(alert)
            
            if self.config.getboolean('SLACK', 'enabled', fallback=False):
                await self.send_slack_alert(alert)
            
            if self.config.getboolean('DISCORD', 'enabled', fallback=False):
                await self.send_discord_alert(alert)
                
        except Exception as e:
            print(f"Notification error: {e}")
    
    async def send_email_alert(self, alert: ContinuousAlert):
        try:
            smtp_server = self.config.get('EMAIL', 'smtp_server')
            smtp_port = self.config.getint('EMAIL', 'smtp_port')
            username = self.config.get('EMAIL', 'username')
            password = self.config.get('EMAIL', 'password')
            recipients = self.config.get('EMAIL', 'recipients').split(',')
            
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"NetPulse Alert: {alert.title}"
            
            body = f"""
NetPulse Elite Alert

Severity: {alert.severity.upper()}
Target: {alert.target}
Category: {alert.category}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

Description:
{alert.description}

Recommended Actions:
{chr(10).join('- ' + action for action in alert.recommended_actions)}

Evidence:
{json.dumps(alert.evidence, indent=2)}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)
                
        except Exception as e:
            print(f"Email notification error: {e}")
    
    async def send_slack_alert(self, alert: ContinuousAlert):
        try:
            webhook_url = self.config.get('SLACK', 'webhook_url')
            
            color_map = {
                'critical': '#FF0000',
                'high': '#FF6B00', 
                'medium': '#FFD700',
                'low': '#36A64F',
                'info': '#36A64F'
            }
            
            payload = {
                "attachments": [{
                    "color": color_map.get(alert.severity, '#808080'),
                    "title": f"🚨 NetPulse Alert: {alert.title}",
                    "fields": [
                        {"title": "Severity", "value": alert.severity.upper(), "short": True},
                        {"title": "Target", "value": alert.target, "short": True},
                        {"title": "Category", "value": alert.category, "short": True},
                        {"title": "Time", "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'), "short": True},
                        {"title": "Description", "value": alert.description, "short": False}
                    ]
                }]
            }
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
        except Exception as e:
            print(f"Slack notification error: {e}")
    
    async def send_discord_alert(self, alert: ContinuousAlert):
        try:
            webhook_url = self.config.get('DISCORD', 'webhook_url')
            
            color_map = {
                'critical': 0xFF0000,
                'high': 0xFF6B00,
                'medium': 0xFFD700,
                'low': 0x36A64F,
                'info': 0x36A64F
            }
            
            embed = {
                "title": f"🚨 NetPulse Alert",
                "description": alert.title,
                "color": color_map.get(alert.severity, 0x808080),
                "fields": [
                    {"name": "Severity", "value": alert.severity.upper(), "inline": True},
                    {"name": "Target", "value": alert.target, "inline": True},
                    {"name": "Category", "value": alert.category, "inline": True},
                    {"name": "Description", "value": alert.description, "inline": False}
                ],
                "timestamp": alert.timestamp.isoformat()
            }
            
            payload = {"embeds": [embed]}
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
        except Exception as e:
            print(f"Discord notification error: {e}")

class NetPulseEliteContinuous:
    
    def __init__(self):
        self.db = ContinuousNetworkDatabase()
        self.monitoring_engine = ContinuousMonitoringEngine(self.db)
        self.traffic_analyzer = RealTimeTrafficAnalyzer()
        self.notification_system = NotificationSystem()
        self.analysis_engine = NetPulseEliteEngine()
        
        self.monitoring_engine.add_alert_handler(self.notification_system.send_alert_notification)
    
    async def run_single_analysis(self, target: str) -> Dict:
        print(f"{Colors.CYAN}🔍 Running comprehensive analysis for {target}...{Colors.END}")
        
        results = await self.analysis_engine.analyze_target_comprehensive(target)
        
        self.db.store_analysis_result(target, 'single_analysis', results)
        
        return results
    
    async def start_continuous_monitoring(self, targets: List[str]):
        print(f"{Colors.BOLD}{Colors.CYAN}🚀 Starting NetPulse Elite Continuous Platform{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        
        for target in targets:
            self.monitoring_engine.add_target(target)
        
        monitoring_task = asyncio.create_task(self.monitoring_engine.start_monitoring())
        
        traffic_task = None
        interface = os.environ.get('NETPULSE_INTERFACE')
        if interface:
            self.traffic_analyzer.interface = interface
            traffic_task = asyncio.create_task(self.traffic_analyzer.start_continuous_capture())
        
        try:
            if traffic_task:
                await asyncio.gather(monitoring_task, traffic_task)
            else:
                await monitoring_task
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Shutting down continuous monitoring...{Colors.END}")
    
    def get_monitoring_dashboard(self) -> Dict:
        dashboard = {
            'active_alerts': [],
            'monitoring_status': {},
            'recent_analyses': {},
            'performance_summary': {}
        }
        
        dashboard['active_alerts'] = [
            {
                'target': alert.target,
                'severity': alert.severity,
                'title': alert.title,
                'timestamp': alert.timestamp.isoformat()
            }
            for alert in self.db.get_active_alerts()
        ]
        
        for target in self.monitoring_engine.targets:
            history = self.db.get_analysis_history(target, limit=5)
            dashboard['monitoring_status'][target] = {
                'last_analysis': history[0] if history else None,
                'trend': self.calculate_trend(history)
            }
        
        return dashboard
    
    def calculate_trend(self, history: List[Dict]) -> str:
        if len(history) < 2:
            return 'stable'
        
        scores = [h['security_score'] for h in history if h['security_score']]
        if len(scores) < 2:
            return 'stable'
        
        recent_avg = statistics.mean(scores[:3]) if len(scores) >= 3 else scores[0]
        older_avg = statistics.mean(scores[-3:]) if len(scores) >= 3 else scores[-1]
        
        if recent_avg > older_avg + 5:
            return 'improving'
        elif recent_avg < older_avg - 5:
            return 'degrading'
        else:
            return 'stable'

class NetPulseEliteCLI:
    
    def __init__(self):
        self.platform = NetPulseEliteContinuous()
        
    def create_parser(self):
        parser = argparse.ArgumentParser(
            description='NetPulse Elite - Continuous Network Intelligence Platform',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
NetPulse Elite - Advanced Continuous Network Monitoring

Operation Modes:

1. Single Analysis (Default):
   python netpulse_elite.py google.com
   python netpulse_elite.py 192.168.1.1 -o results.json

2. Continuous Monitoring:
   python netpulse_elite.py --monitor google.com,github.com,stackoverflow.com
   python netpulse_elite.py --monitor-file targets.txt

3. Traffic Analysis:
   python netpulse_elite.py --traffic-analysis --interface eth0
   python netpulse_elite.py --traffic-analysis --interface wlan0 --continuous

4. Combined Mode:
   python netpulse_elite.py --monitor google.com --traffic-analysis --interface eth0

Features automatically included:
• Comprehensive network intelligence gathering
• Continuous security monitoring and alerting  
• Real-time traffic analysis and threat detection
• Performance monitoring and degradation alerts
• Baseline establishment and change detection
• Multi-channel notifications (Email, Slack, Discord)
• Historical trending and anomaly detection
• Automated incident response recommendations
            """
        )
        
        parser.add_argument('target', nargs='?',
                          help='Target for single analysis (hostname, domain, or IP)')
        
        parser.add_argument('--monitor', 
                          help='Comma-separated list of targets for continuous monitoring')
        
        parser.add_argument('--monitor-file',
                          help='File containing targets for continuous monitoring (one per line)')
        
        parser.add_argument('--traffic-analysis', action='store_true',
                          help='Enable real-time traffic analysis')
        
        parser.add_argument('--interface',
                          help='Network interface for traffic analysis')
        
        parser.add_argument('-o', '--output',
                          help='Save results to JSON file')
        
        parser.add_argument('--dashboard', action='store_true',
                          help='Display monitoring dashboard')
        
        parser.add_argument('--alerts', action='store_true',
                          help='Show active alerts')
        
        parser.add_argument('--continuous', action='store_true',
                          help='Run in continuous mode (never exit)')
        
        parser.add_argument('--quiet', action='store_true',
                          help='Reduce output verbosity')
        
        parser.add_argument('-v', '--verbose', action='store_true',
                          help='Increase output verbosity')
        
        parser.add_argument('--no-color', action='store_true',
                          help='Disable colored output')
                          
        return parser
    
    async def run_application(self, args):
        try:
            if args.no_color:
                for attr in dir(Colors):
                    if not attr.startswith('_'):
                        setattr(Colors, attr, '')
            
            if args.dashboard:
                await self.display_dashboard()
                return
            
            if args.alerts:
                await self.display_active_alerts()
                return
            
            if args.traffic_analysis and not args.monitor and not args.target:
                self.platform.traffic_analyzer.interface = args.interface
                await self.platform.traffic_analyzer.start_continuous_capture()
                return
            
            if args.monitor or args.monitor_file:
                targets = []
                
                if args.monitor:
                    targets.extend(args.monitor.split(','))
                
                if args.monitor_file:
                    with open(args.monitor_file, 'r') as f:
                        targets.extend(line.strip() for line in f if line.strip())
                
                if targets:
                    if args.traffic_analysis and args.interface:
                        os.environ['NETPULSE_INTERFACE'] = args.interface
                    
                    await self.platform.start_continuous_monitoring(targets)
                else:
                    print(f"{Colors.RED}No targets specified for monitoring{Colors.END}")
                return
            
            if args.target:
                results = await self.platform.run_single_analysis(args.target)
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    print(f"\n{Colors.GREEN}✓ Results saved to {args.output}{Colors.END}")
                
                self.display_analysis_summary(results)
                
                return
            
            print(f"{Colors.RED}Error: Must specify target, --monitor, or --traffic-analysis{Colors.END}")
            print(f"Use --help for usage information")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}NetPulse Elite terminated by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}Application error: {e}{Colors.END}")
            if args.verbose:
                import traceback
                traceback.print_exc()
    
    def display_analysis_summary(self, results: Dict[str, Any]):
        print(f"\n{Colors.BOLD}{Colors.CYAN}ANALYSIS SUMMARY{Colors.END}")
        print(f"{Colors.BLUE}{'='*50}{Colors.END}")
        
        metadata = results.get('metadata', {})
        security_assessment = results.get('security_assessment', {})
        network_host = results.get('network_host', {})
        reconnaissance = results.get('reconnaissance', {})
        port_analysis = results.get('port_analysis', [])
        
        target = metadata.get('target', 'Unknown')
        duration = metadata.get('analysis_duration', 'Unknown')
        modules = len(metadata.get('modules_executed', []))
        
        security_score = security_assessment.get('overall_score', 0)
        risk_level = security_assessment.get('risk_level', 'Unknown')
        
        open_ports = len(port_analysis)
        subdomains = len(reconnaissance.get('subdomains', {}).get('discovered', []))
        technologies = len(reconnaissance.get('technology', {}).get('frameworks', []))
        
        network_info = network_host.get('network_info', {})
        organization = network_info.get('organization', 'Unknown')
        country = network_info.get('country', 'Unknown')
        cdn_provider = network_info.get('cdn_provider', 'None')
        
        print(f"Target Analyzed: {Colors.CYAN}{target}{Colors.END}")
        print(f"Analysis Duration: {duration}")
        print(f"Modules Executed: {modules}")
        print(f"")
        print(f"Security Score: {Colors.CYAN}{security_score}/100{Colors.END}")
        print(f"Risk Level: {Colors.YELLOW}{risk_level}{Colors.END}")
        print(f"")
        print(f"Services Discovered: {Colors.GREEN}{open_ports}{Colors.END}")
        print(f"Subdomains Found: {Colors.GREEN}{subdomains}{Colors.END}")
        print(f"Technologies Detected: {Colors.GREEN}{technologies}{Colors.END}")
        print(f"")
        print(f"Organization: {organization}")
        print(f"Country: {country}")
        print(f"CDN Protection: {cdn_provider}")
        
        print(f"\n{Colors.GREEN}✓ Comprehensive analysis completed successfully{Colors.END}")
        print(f"{Colors.BLUE}{'='*50}{Colors.END}\n")
    
    async def display_dashboard(self):
        dashboard = self.platform.get_monitoring_dashboard()
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Monitoring Dashboard{Colors.END}")
        print(f"{Colors.BLUE}{'='*60}{Colors.END}")
        
        alerts = dashboard['active_alerts']
        if alerts:
            print(f"\n{Colors.BOLD}🚨 Active Alerts ({len(alerts)}){Colors.END}")
            for alert in alerts[:10]:
                severity_color = {
                    'critical': Colors.RED,
                    'high': Colors.RED,
                    'medium': Colors.YELLOW,
                    'low': Colors.BLUE
                }.get(alert['severity'], Colors.WHITE)
                
                print(f"  {severity_color}[{alert['severity'].upper()}]{Colors.END} "
                      f"{alert['target']} - {alert['title']}")
        else:
            print(f"\n{Colors.GREEN}✓ No active alerts{Colors.END}")
        
        monitoring_status = dashboard['monitoring_status']
        if monitoring_status:
            print(f"\n{Colors.BOLD}📊 Monitoring Status{Colors.END}")
            for target, status in monitoring_status.items():
                if status['last_analysis']:
                    score = status['last_analysis']['security_score']
                    risk = status['last_analysis']['risk_level']
                    trend = status['trend']
                    
                    trend_icon = {'improving': '↗️', 'degrading': '↘️', 'stable': '→'}.get(trend, '→')
                    score_color = Colors.GREEN if score >= 75 else Colors.YELLOW if score >= 50 else Colors.RED
                    
                    print(f"  {target}: {score_color}Score={score}/100{Colors.END} "
                          f"Risk={risk} Trend={trend_icon}")
                else:
                    print(f"  {target}: {Colors.YELLOW}No recent analysis{Colors.END}")
        
        print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
    
    async def display_active_alerts(self):
        alerts = self.platform.db.get_active_alerts()
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}NetPulse Elite - Active Alerts{Colors.END}")
        print(f"{Colors.BLUE}{'='*60}{Colors.END}")
        
        if not alerts:
            print(f"\n{Colors.GREEN}✓ No active alerts{Colors.END}")
            return
        
        severity_groups = defaultdict(list)
        for alert in alerts:
            severity_groups[alert.severity].append(alert)
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in severity_groups:
                severity_color = {
                    'critical': Colors.RED + Colors.BOLD,
                    'high': Colors.RED,
                    'medium': Colors.YELLOW,
                    'low': Colors.BLUE,
                    'info': Colors.CYAN
                }.get(severity, Colors.WHITE)
                
                print(f"\n{severity_color}{severity.upper()} ALERTS ({len(severity_groups[severity])}){Colors.END}")
                
                for alert in severity_groups[severity]:
                    print(f"  📍 {alert.target} - {alert.title}")
                    print(f"     {alert.description}")
                    print(f"     ⏰ {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                    print()
        
        print(f"{Colors.BLUE}{'='*60}{Colors.END}")

def display_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██║     ███████╗█████╗  
██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝███████╗███████║███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝

{Colors.PURPLE}███████╗██╗     ██╗████████╗███████╗{Colors.END}
{Colors.PURPLE}██╔════╝██║     ██║╚══██╔══╝██╔════╝{Colors.END}  
{Colors.PURPLE}█████╗  ██║     ██║   ██║   █████╗  {Colors.END}
{Colors.PURPLE}██╔══╝  ██║     ██║   ██║   ██╔══╝  {Colors.END}
{Colors.PURPLE}███████╗███████╗██║   ██║   ███████╗{Colors.END}
{Colors.PURPLE}╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝{Colors.END}

{Colors.BOLD}Continuous Network Intelligence Platform{Colors.END}
{Colors.CYAN}• Comprehensive Network Analysis & Intelligence Gathering{Colors.END}
{Colors.CYAN}• Continuous Security Monitoring & Change Detection{Colors.END}
{Colors.CYAN}• Real-time Traffic Analysis & Threat Detection{Colors.END}
{Colors.CYAN}• Automated Alerting & Multi-channel Notifications{Colors.END}
{Colors.CYAN}• Performance Monitoring & Degradation Detection{Colors.END}
{Colors.CYAN}• Historical Trending & Anomaly Detection{Colors.END}

{Colors.GREEN}Version 2.0 Elite - Continuous Intelligence Platform{Colors.END}
{Colors.BLUE}Single Analysis | Continuous Monitoring | Real-time Traffic Analysis{Colors.END}
"""
    print(banner)

def check_dependencies():
    required_modules = [
        'scapy', 'requests', 'numpy', 'sklearn', 'dns', 
        'paramiko', 'nmap', 'telnetlib3', 'sqlite3', 'pyshark'
    ]
    
    missing = []
    for module in required_modules:
        try:
            if module == 'sklearn':
                __import__('sklearn')
            elif module == 'dns':
                __import__('dns.resolver')
            elif module == 'sqlite3':
                import sqlite3
            elif module == 'pyshark':
                import pyshark
            else:
                __import__(module)
        except ImportError:
            if module == 'dns':
                missing.append('dnspython')
            elif module == 'sklearn':
                missing.append('scikit-learn')
            elif module == 'pyshark':
                missing.append('pyshark (requires TShark/Wireshark)')
            else:
                missing.append(module)
    
    if missing:
        print(f"{Colors.RED}Missing required dependencies:{Colors.END}")
        for dep in missing:
            print(f"  • {dep}")
        print(f"\n{Colors.YELLOW}Install with: pip install {' '.join([d for d in missing if 'TShark' not in d])}{Colors.END}")
        if 'pyshark (requires TShark/Wireshark)' in missing:
            print(f"{Colors.YELLOW}  For pyshark, ensure Wireshark/TShark is installed and in your PATH.{Colors.END}")
        return False
    
    return True

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('netpulse_elite.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

async def main():
    display_banner()
    setup_logging()
    
    if not check_dependencies():
        sys.exit(1)
    
    cli = NetPulseEliteCLI()
    parser = cli.create_parser()
    
    if len(sys.argv) == 1:
        print(f"{Colors.YELLOW}NetPulse Elite - Interactive Mode{Colors.END}")
        print(f"Choose operation mode:")
        print(f"1. Single target analysis")
        print(f"2. Continuous monitoring")
        print(f"3. Traffic analysis")
        print(f"4. View dashboard")
        print(f"5. View alerts")
        
        try:
            choice = input(f"\nEnter choice (1-5): ").strip()
            
            if choice == '1':
                target = input("Enter target (hostname/IP): ").strip()
                if target:
                    args = parser.parse_args([target])
                    await cli.run_application(args)
            elif choice == '2':
                targets_input = input("Enter targets (comma-separated): ").strip()
                if targets_input:
                    targets = [t.strip() for t in targets_input.split(',')]
                    args = parser.parse_args(['--monitor', targets_input])
                    await cli.run_application(args)
            elif choice == '3':
                interface = input("Enter interface (or press Enter for default): ").strip() or None
                args_list = ['--traffic-analysis']
                if interface:
                    args_list.extend(['--interface', interface])
                args = parser.parse_args(args_list)
                await cli.run_application(args)
            elif choice == '4':
                args = parser.parse_args(['--dashboard'])
                await cli.run_application(args)
            elif choice == '5':
                args = parser.parse_args(['--alerts'])
                await cli.run_application(args)
            else:
                print("Invalid choice")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting...{Colors.END}")
        
        return
    
    args = parser.parse_args()
    await cli.run_application(args)

if __name__ == "__main__":
    asyncio.run(main())