#!/usr/bin/env python3
"""
RavenTrace - Port Scanner Module

This module provides TCP port scanning capabilities for the RavenTrace toolkit,
implementing secure and efficient scanning techniques with proper error handling
and rate limiting to avoid detection.

Author: RavenTrace Team
Version: 1.0.0
License: Educational Use Only
"""

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import os
import random
import socket
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("raventrace.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("raventrace.port_scanner")


class ScanType(Enum):
    """Enum for supported scan types."""
    TCP_CONNECT = auto()
    TCP_SYN = auto()  # Requires root privileges
    TCP_NULL = auto()  # Requires root privileges
    TCP_FIN = auto()   # Requires root privileges
    TCP_XMAS = auto()  # Requires root privileges


@dataclass
class ScanConfig:
    """Configuration dataclass for port scanning settings."""
    scan_type: ScanType = ScanType.TCP_CONNECT
    timeout: float = 1.0
    max_threads: int = 100
    delay: float = 0.0
    randomize_ports: bool = True
    randomize_hosts: bool = True
    common_ports_only: bool = False
    verbose: bool = False
    output_file: Optional[str] = None
    ports: List[int] = field(default_factory=list)


class PortScanner:
    """
    Main class for port scanning in RavenTrace.
    
    This class provides methods to scan for open ports on target hosts
    using various techniques with proper rate limiting and randomization.
    """
    
    # Common ports to scan by default
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ]
    
    def __init__(self, config: ScanConfig):
        """Initialize the scanner with the given configuration."""
        self.config = config
        
        # Set up ports to scan
        if not self.config.ports:
            if self.config.common_ports_only:
                self.ports_to_scan = self.COMMON_PORTS.copy()
            else:
                self.ports_to_scan = list(range(1, 1025))  # Default: scan first 1024 ports
        else:
            self.ports_to_scan = self.config.ports.copy()
            
        # Randomize ports if configured
        if self.config.randomize_ports:
            random.shuffle(self.ports_to_scan)
            
        # Results storage
        self.results = {}
        
    def scan_host(self, host: str) -> Dict[int, bool]:
        """
        Scan a single host for open ports.
        
        Args:
            host: The target host IP or hostname
            
        Returns:
            Dict[int, bool]: Dictionary mapping port numbers to open status
        """
        results = {}
        
        try:
            # Validate host
            try:
                socket.gethostbyname(host)
            except socket.gaierror:
                logger.error(f"Invalid host: {host}")
                return results
                
            logger.info(f"Scanning host: {host}")
            
            # Use appropriate scan method based on scan type
            if self.config.scan_type == ScanType.TCP_CONNECT:
                results = self._tcp_connect_scan(host)
            elif self.config.scan_type in (ScanType.TCP_SYN, ScanType.TCP_NULL, 
                                          ScanType.TCP_FIN, ScanType.TCP_XMAS):
                # These scan types require root privileges and raw sockets
                if os.geteuid() != 0:
                    logger.error(f"{self.config.scan_type.name} scan requires root privileges")
                    return results
                    
                # Import scapy only when needed (and if available)
                try:
                    import scapy.all as scapy
                    if self.config.scan_type == ScanType.TCP_SYN:
                        results = self._tcp_syn_scan(host, scapy)
                    elif self.config.scan_type == ScanType.TCP_NULL:
                        results = self._tcp_null_scan(host, scapy)
                    elif self.config.scan_type == ScanType.TCP_FIN:
                        results = self._tcp_fin_scan(host, scapy)
                    elif self.config.scan_type == ScanType.TCP_XMAS:
                        results = self._tcp_xmas_scan(host, scapy)
                except ImportError:
                    logger.error("Scapy library not available. Install with: pip install scapy")
                    return results
            else:
                logger.error(f"Unsupported scan type: {self.config.scan_type}")
                return results
                
            # Store results
            self.results[host] = results
            
            # Log open ports
            open_ports = [port for port, is_open in results.items() if is_open]
            if open_ports:
                logger.info(f"Open ports on {host}: {', '.join(map(str, open_ports))}")
            else:
                logger.info(f"No open ports found on {host}")
                
            return results
            
        except Exception as e:
            logger.error(f"Error scanning host {host}: {e}")
            return results
            
    def _tcp_connect_scan(self, host: str) -> Dict[int, bool]:
        """
        Perform a TCP connect scan on the target host.
        
        Args:
            host: The target host
            
        Returns:
            Dict[int, bool]: Dictionary mapping port numbers to open status
        """
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            # Submit scan tasks for each port
            future_to_port = {
                executor.submit(self._check_port_tcp_connect, host, port): port
                for port in self.ports_to_scan
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    results[port] = is_open
                    
                    if is_open and self.config.verbose:
                        logger.info(f"Port {port} is open on {host}")
                        
                except Exception as e:
                    logger.error(f"Error checking port {port} on {host}: {e}")
                    results[port] = False
                    
                # Add delay if configured
                if self.config.delay > 0:
                    time.sleep(self.config.delay)
                    
        return results
        
    def _check_port_tcp_connect(self, host: str, port: int) -> bool:
        """
        Check if a port is open using TCP connect method.
        
        Args:
            host: The target host
            port: The port to check
            
        Returns:
            bool: True if port is open, False otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        
        try:
            sock.connect((host, port))
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False
        except Exception as e:
            if self.config.verbose:
                logger.debug(f"Error connecting to {host}:{port} - {e}")
            return False
        finally:
            sock.close()
            
    def _tcp_syn_scan(self, host: str, scapy) -> Dict[int, bool]:
        """
        Perform a TCP SYN scan using scapy.
        
        Args:
            host: The target host
            scapy: The scapy module
            
        Returns:
            Dict[int, bool]: Dictionary mapping port numbers to open status
        """
        results = {}
        
        for port in self.ports_to_scan:
            # Create SYN packet
            syn_packet = scapy.IP(dst=host)/scapy.TCP(dport=port, flags="S")
            
            # Send packet and wait for response
            response = scapy.sr1(syn_packet, timeout=self.config.timeout, verbose=0)
            
            # Process response
            if response and response.haslayer(scapy.TCP):
                # Check if SYN-ACK received (port open)
                if response.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = scapy.IP(dst=host)/scapy.TCP(
                        dport=port, 
                        flags="R", 
                        seq=response.getlayer(scapy.TCP).ack
                    )
                    scapy.send(rst_packet, verbose=0)
                    results[port] = True
                    
                    if self.config.verbose:
                        logger.info(f"Port {port} is open on {host}")
                else:
                    results[port] = False
            else:
                results[port] = False
                
            # Add delay if configured
            if self.config.delay > 0:
                time.sleep(self.config.delay)
                
        return results
        
    def _tcp_null_scan(self, host: str, scapy) -> Dict[int, bool]:
        """
        Perform a TCP NULL scan using scapy.
        
        Args:
            host: The target host
            scapy: The scapy module
            
        Returns:
            Dict[int, bool]: Dictionary mapping port numbers to open status
        """
        results = {}
        
        for port in self.ports_to_scan:
            # Create NULL packet (no flags set)
            null_packet = scapy.IP(dst=host)/scapy.TCP(dport=port, flags="")
            
            # Send packet and wait for response
            response = scapy.sr1(null_packet, timeout=self.config.timeout, verbose=0)
            
            # Process response - no response or ICMP error typically means open/filtered
            if response is None:
                results[port] = True
                if self.config.verbose:
                    logger.info(f"Port {port} is open|filtered on {host}")
            elif response.haslayer(scapy.TCP):
                # RST response means closed
                if response.getlayer(scapy.TCP).flags & 0x04:  # RST flag
                    results[port] = False
                else:
                    results[port] = True
            elif response.haslayer(scapy.ICMP):
                # ICMP error means filtered
                results[port] = False
            else:
                results[port] = False
                
            # Add delay if configured
            if self.config.delay > 0:
                time.sleep(self.config.delay)
                
        return results
        
    def _tcp_fin_scan(self, host: str, scapy) -> Dict[int, bool]:
        """
        Perform a TCP FIN scan using scapy.
        
        Args:
            host: The target host
            scapy: The scapy module
            
        Returns:
            Dict[int, bool]: Dictionary mapping port numbers to open status
        """
        results = {}
        
        for port in self.ports_to_scan:
            # Create FIN packet
            fin_packet = scapy.IP(dst=host)/scapy.TCP(dport=port, flags="F")
            
            # Send packet and wait for response
            response = scapy.sr1(fin_packet, timeout=self.config.timeout, verbose=0)
            
            # Process response - no response typically means open/filtered
            if response is None:
                results[port] = True
                if self.config.verbose:
                    logger.info(f"Port {port} is open|filtered on {host}")
            elif response.haslayer(scapy.TCP):
                # RST response means closed
                if response.getlayer(scapy.TCP).flags & 0x04:  # RST flag
                    results[port] = False
                else:
                    results[port] = True
            elif response.haslayer(scapy.ICMP):
                # ICMP error means filtered
                results[port] = False
            else:
                results[port] = False
                
            # Add delay if configured
            if self.config.delay > 0:
                time.sleep(self.config.delay)
                
        return results
        
    def _tcp_xmas_scan(self, host: str, scapy) -> Dict[int, bool]:
        """
        Perform a TCP XMAS scan using scapy.
        
        Args:
            host: The target host
            scapy: The scapy module
            
        Returns:
            Dict[int, bool]: Dictionary mapping port numbers to open status
        """
        results = {}
        
        for port in self.ports_to_scan:
            # Create XMAS packet (FIN, PSH, URG flags set)
            xmas_packet = scapy.IP(dst=host)/scapy.TCP(dport=port, flags="FPU")
            
            # Send packet and wait for response
            response = scapy.sr1(xmas_packet, timeout=self.config.timeout, verbose=0)
            
            # Process response - no response typically means open/filtered
            if response is None:
                results[port] = True
                if self.config.verbose:
                    logger.info(f"Port {port} is open|filtered on {host}")
            elif response.haslayer(scapy.TCP):
                # RST response means closed
                if response.getlayer(scapy.TCP).flags & 0x04:  # RST flag
                    results[port] = False
                else:
                    results[port] = True
            elif response.haslayer(scapy.ICMP):
                # ICMP error means filtered
                results[port] = False
            else:
                results[port] = False
                
            # Add delay if configured
            if self.config.delay > 0:
                time.sleep(self.config.delay)
                
        return results
        
    def scan_network(self, network: str) -> Dict[str, Dict[int, bool]]:
        """
        Scan all hosts in a network range.
        
        Args:
            network: The target network in CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            Dict[str, Dict[int, bool]]: Dictionary mapping hosts to port scan results
        """
        try:
            # Parse network range
            network_range = ipaddress.ip_network(network, strict=False)
            hosts = [str(ip) for ip in network_range.hosts()]
            
            # Randomize hosts if configured
            if self.config.randomize_hosts:
                random.shuffle(hosts)
                
            logger.info(f"Scanning network: {network} ({len(hosts)} hosts)")
            
            # Scan each host
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, self.config.max_threads)) as executor:
                # Submit scan tasks for each host
                future_to_host = {
                    executor.submit(self.scan_host, host): host
                    for host in hosts
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        future.result()  # Results already stored in self.results
                    except Exception as e:
                        logger.error(f"Error scanning host {host}: {e}")
                        
  
(Content truncated due to size limit. Use line ranges to read in chunks)