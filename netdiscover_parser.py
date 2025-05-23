#!/usr/bin/env python3
"""
RavenTrace - Netdiscover Parser Module

This module parses the output of netdiscover tool to identify live hosts on a network.
It provides functionality to process raw netdiscover output and extract useful information
about discovered hosts.

Author: RavenTrace Team
Version: 1.0.0
License: Educational Use Only
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
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
logger = logging.getLogger("raventrace.netdiscover_parser")


@dataclass
class HostInfo:
    """Class for storing information about a discovered host."""
    ip_address: str
    mac_address: str
    count: int = 0
    vendor: str = "Unknown"
    hostname: Optional[str] = None
    last_seen: Optional[datetime] = None
    

class NetdiscoverParser:
    """
    Parser for netdiscover output to extract host information.
    
    This class provides methods to parse the output of the netdiscover tool,
    extract host information, and save the results in various formats.
    """
    
    def __init__(self, mac_vendor_file: Optional[str] = None):
        """
        Initialize the parser.
        
        Args:
            mac_vendor_file: Path to a MAC vendor database file (optional)
        """
        self.hosts = {}
        self.mac_vendors = {}
        
        # Load MAC vendor database if provided
        if mac_vendor_file and os.path.exists(mac_vendor_file):
            self._load_mac_vendors(mac_vendor_file)
            
    def _load_mac_vendors(self, filename: str) -> None:
        """
        Load MAC address to vendor mappings from a file.
        
        Args:
            filename: Path to the MAC vendor database file
        """
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            mac_prefix = parts[0].upper()
                            vendor = parts[1]
                            self.mac_vendors[mac_prefix] = vendor
                            
            logger.info(f"Loaded {len(self.mac_vendors)} MAC vendor entries")
            
        except Exception as e:
            logger.error(f"Error loading MAC vendor database: {e}")
            
    def _lookup_vendor(self, mac_address: str) -> str:
        """
        Look up the vendor for a MAC address.
        
        Args:
            mac_address: The MAC address to look up
            
        Returns:
            str: The vendor name or "Unknown"
        """
        if not mac_address:
            return "Unknown"
            
        # Normalize MAC address
        mac = mac_address.upper().replace(':', '').replace('-', '')
        
        # Try different prefix lengths
        for prefix_len in [6, 8, 10]:
            prefix = mac[:prefix_len]
            if prefix in self.mac_vendors:
                return self.mac_vendors[prefix]
                
        return "Unknown"
        
    def parse_file(self, filename: str) -> Dict[str, HostInfo]:
        """
        Parse netdiscover output from a file.
        
        Args:
            filename: Path to the netdiscover output file
            
        Returns:
            Dict[str, HostInfo]: Dictionary of discovered hosts
        """
        try:
            with open(filename, 'r') as f:
                content = f.read()
                return self.parse_output(content)
                
        except Exception as e:
            logger.error(f"Error parsing netdiscover output file: {e}")
            return {}
            
    def parse_output(self, output: str) -> Dict[str, HostInfo]:
        """
        Parse raw netdiscover output.
        
        Args:
            output: Raw netdiscover output string
            
        Returns:
            Dict[str, HostInfo]: Dictionary of discovered hosts
        """
        # Regular expression to match netdiscover output lines
        pattern = r'\s*(\d+)\s+([0-9.]+)\s+([0-9a-fA-F:]+)\s+(\d+)\s+(.*)'
        
        for line in output.splitlines():
            match = re.match(pattern, line)
            if match:
                try:
                    # Extract fields
                    num, ip, mac, count, vendor = match.groups()
                    
                    # Validate IP address
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        logger.warning(f"Invalid IP address: {ip}")
                        continue
                        
                    # Validate MAC address
                    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                        logger.warning(f"Invalid MAC address: {mac}")
                        continue
                        
                    # Look up vendor if not provided or "Unknown"
                    if not vendor or vendor.strip() == "Unknown":
                        vendor = self._lookup_vendor(mac)
                        
                    # Create or update host info
                    if ip in self.hosts:
                        # Update existing host
                        self.hosts[ip].mac_address = mac
                        self.hosts[ip].count += int(count)
                        self.hosts[ip].vendor = vendor
                        self.hosts[ip].last_seen = datetime.now()
                    else:
                        # Add new host
                        self.hosts[ip] = HostInfo(
                            ip_address=ip,
                            mac_address=mac,
                            count=int(count),
                            vendor=vendor,
                            last_seen=datetime.now()
                        )
                        
                except Exception as e:
                    logger.error(f"Error parsing line: {line} - {e}")
                    
        return self.hosts
        
    def run_netdiscover(self, interface: str, range: Optional[str] = None, 
                       count: int = 1, timeout: int = 30) -> Dict[str, HostInfo]:
        """
        Run netdiscover and parse the output.
        
        Args:
            interface: Network interface to use
            range: IP range to scan (CIDR notation)
            count: Number of discovery packets to send
            timeout: Timeout in seconds
            
        Returns:
            Dict[str, HostInfo]: Dictionary of discovered hosts
        """
        try:
            # Check if netdiscover is installed
            try:
                subprocess.run(['which', 'netdiscover'], 
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                logger.error("netdiscover not found. Please install it first.")
                return {}
                
            # Build command
            cmd = ['sudo', 'netdiscover', '-i', interface, '-c', str(count), '-P']
            
            if range:
                cmd.extend(['-r', range])
                
            # Run netdiscover
            logger.info(f"Running netdiscover on {interface}" + 
                       (f" for range {range}" if range else ""))
                       
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if process.returncode != 0:
                logger.error(f"netdiscover failed: {process.stderr}")
                return {}
                
            # Parse output
            return self.parse_output(process.stdout)
            
        except subprocess.TimeoutExpired:
            logger.error(f"netdiscover timed out after {timeout} seconds")
            return {}
        except Exception as e:
            logger.error(f"Error running netdiscover: {e}")
            return {}
            
    def resolve_hostnames(self) -> None:
        """Attempt to resolve hostnames for discovered IP addresses."""
        import socket
        
        for ip, host_info in self.hosts.items():
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                host_info.hostname = hostname
                logger.info(f"Resolved {ip} to {hostname}")
            except (socket.herror, socket.gaierror):
                # Could not resolve hostname
                pass
                
    def save_results(self, filename: str, format: str = 'txt') -> None:
        """
        Save the parsed results to a file.
        
        Args:
            filename: Output filename
            format: Output format ('txt', 'csv', or 'json')
        """
        try:
            # Create results directory if it doesn't exist
            results_dir = Path("results")
            results_dir.mkdir(exist_ok=True)
            
            # Full path to output file
            output_path = results_dir / filename
            
            if format.lower() == 'txt':
                self._save_as_text(output_path)
            elif format.lower() == 'csv':
                self._save_as_csv(output_path)
            elif format.lower() == 'json':
                self._save_as_json(output_path)
            else:
                logger.error(f"Unsupported output format: {format}")
                return
                
            logger.info(f"Results saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error saving results to {filename}: {e}")
            
    def _save_as_text(self, filename: Path) -> None:
        """
        Save results as a formatted text file.
        
        Args:
            filename: Output file path
        """
        with open(filename, 'w') as f:
            f.write("RavenTrace Netdiscover Results\n")
            f.write("============================\n\n")
            
            f.write(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total hosts discovered: {len(self.hosts)}\n\n")
            
            # Sort hosts by IP address
            sorted_ips = sorted(self.hosts.keys(), 
                               key=lambda ip: [int(octet) for octet in ip.split('.')])
            
            for ip in sorted_ips:
                host = self.hosts[ip]
                f.write(f"Host: {ip}\n")
                f.write(f"  MAC Address: {host.mac_address}\n")
                f.write(f"  Vendor: {host.vendor}\n")
                
                if host.hostname:
                    f.write(f"  Hostname: {host.hostname}\n")
                    
                if host.last_seen:
                    f.write(f"  Last seen: {host.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    
                f.write(f"  Packet count: {host.count}\n")
                f.write("\n")
                
    def _save_as_csv(self, filename: Path) -> None:
        """
        Save results as a CSV file.
        
        Args:
            filename: Output file path
        """
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['IP Address', 'MAC Address', 'Vendor', 'Hostname', 
                           'Last Seen', 'Packet Count'])
            
            # Sort hosts by IP address
            sorted_ips = sorted(self.hosts.keys(), 
                               key=lambda ip: [int(octet) for octet in ip.split('.')])
            
            # Write data
            for ip in sorted_ips:
                host = self.hosts[ip]
                writer.writerow([
                    ip,
                    host.mac_address,
                    host.vendor,
                    host.hostname or '',
                    host.last_seen.strftime('%Y-%m-%d %H:%M:%S') if host.last_seen else '',
                    host.count
                ])
                
    def _save_as_json(self, filename: Path) -> None:
        """
        Save results as a JSON file.
        
        Args:
            filename: Output file path
        """
        # Convert hosts to serializable format
        hosts_data = {}
        
        for ip, host in self.hosts.items():
            hosts_data[ip] = {
                'ip_address': host.ip_address,
                'mac_address': host.mac_address,
                'vendor': host.vendor,
                'hostname': host.hostname,
                'last_seen': host.last_seen.isoformat() if host.last_seen else None,
                'count': host.count
            }
            
        # Add metadata
        data = {
            'scan_time': datetime.now().isoformat(),
            'total_hosts': len(self.hosts),
            'hosts': hosts_data
        }
        
        # Write to file
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="RavenTrace Netdiscover Parser")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-f", "--file", help="Netdiscover output file to parse")
    input_group.add_argument("-i", "--interface", help="Network interface to use for live scanning")
    
    # Scan options
    parser.add_argument("-r", "--range", help="IP range to scan (CIDR notation)")
    parser.add_argument("-c", "--count", type=int, default=1,
                       help="Number of discovery packets to send (default: 1)")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                       help="Timeout in seconds for live scanning (default: 30)")
    
    # Output options
    parser.add_argument("-o", "--output", default="netdiscover_results",
                       help="Output filename (without extension)")
    parser.add_argument("-F", "--format", choices=["txt", "csv", "json"], default="txt",
                       help="Output format (default: txt)")
    parser.add_argument("-m", "--mac-vendors", help="Path to MAC vendor database file")
    parser.add_argument("-n", "--resolve", action="store_true",
                       help="Attempt to resolve hostnames")
    
    return parser.parse_args()


def main():
    """Main function for the netdiscover parser."""
    args = parse_arguments()
    
    # Create parser
    parser = NetdiscoverParser(args.mac_vendors)
    
    try:
        # Parse input
        if args.file:
            parser.parse_file(args.file)
        elif args.interface:
            parser.run_netdiscover(args.interface, args.range, args.count, args.timeout)
            
        # Resolve hostnames if requested
        if args.resolve:
            parser.resolve_hostnames()
            
        # Save results
        output_filename = f"{args.output}.{args.format}"
        parser.save_results(output_filename, args.format)
        
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
