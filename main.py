#!/usr/bin/env python3
"""
RavenTrace - Main Module

This module provides a unified launcher for the RavenTrace toolkit,
allowing easy access to all components through a single interface.

Author: RavenTrace Team
Version: 1.0.0
License: Educational Use Only
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("raventrace.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("raventrace.main")


def setup_environment():
    """Set up the environment for RavenTrace."""
    # Create necessary directories
    os.makedirs("results", exist_ok=True)
    os.makedirs("certs", exist_ok=True)
    
    # Check for required dependencies
    try:
        import cryptography
        import requests
        logger.info("Core dependencies verified")
    except ImportError as e:
        logger.error(f"Missing required dependency: {e}")
        logger.error("Please install required dependencies: pip install -r requirements.txt")
        sys.exit(1)


def run_port_scanner(args):
    """Run the port scanner module."""
    from port_scanner import main as port_scanner_main
    sys.argv = [sys.argv[0]] + args
    port_scanner_main()


def run_netdiscover_parser(args):
    """Run the netdiscover parser module."""
    from netdiscover_parser import main as netdiscover_parser_main
    sys.argv = [sys.argv[0]] + args
    netdiscover_parser_main()


def run_openvas_integration(args):
    """Run the OpenVAS integration module."""
    from openvas_integration import main as openvas_integration_main
    sys.argv = [sys.argv[0]] + args
    openvas_integration_main()


def run_server(args):
    """Run the server module."""
    from server import main as server_main
    sys.argv = [sys.argv[0]] + args
    server_main()


def run_client(args):
    """Run the client module."""
    from client import main as client_main
    sys.argv = [sys.argv[0]] + args
    client_main()


def run_traffic_obfuscator(args):
    """Run the traffic obfuscator module."""
    from traffic_obfuscator import main as traffic_obfuscator_main
    sys.argv = [sys.argv[0]] + args
    traffic_obfuscator_main()


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="RavenTrace - Modular Red Team Reconnaissance and Remote Operations Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run port scanner on a target
  python main.py scan -t 192.168.1.10 -p 80,443,8080
  
  # Run port scanner on a network
  python main.py scan -n 192.168.1.0/24 -c
  
  # Parse netdiscover output
  python main.py discover -f netdiscover_output.txt -o results
  
  # Run OpenVAS scan
  python main.py openvas --host 192.168.1.10 --username admin --password secret -t 192.168.1.100
  
  # Start server
  python main.py server --port 8443 --generate-cert
  
  # Start client
  python main.py client --host 192.168.1.10 --port 8443
  
  # Use traffic obfuscator
  python main.py obfuscate http 192.168.1.10 8080 "Test message"
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Port scanner
    scan_parser = subparsers.add_parser("scan", help="Run port scanner")
    scan_parser.add_argument("-t", "--target", help="Target host to scan")
    scan_parser.add_argument("-n", "--network", help="Target network to scan (CIDR notation)")
    scan_parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated or range)")
    scan_parser.add_argument("-c", "--common", action="store_true", help="Scan common ports only")
    scan_parser.add_argument("-s", "--scan-type", choices=["connect", "syn", "null", "fin", "xmas"],
                           default="connect", help="Scan type (default: connect)")
    scan_parser.add_argument("-o", "--output", help="Output file for scan results")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    # Netdiscover parser
    discover_parser = subparsers.add_parser("discover", help="Run netdiscover parser")
    discover_parser.add_argument("-f", "--file", help="Netdiscover output file to parse")
    discover_parser.add_argument("-i", "--interface", help="Network interface to use for live scanning")
    discover_parser.add_argument("-r", "--range", help="IP range to scan (CIDR notation)")
    discover_parser.add_argument("-o", "--output", default="netdiscover_results",
                               help="Output filename (without extension)")
    discover_parser.add_argument("-F", "--format", choices=["txt", "csv", "json"], default="txt",
                               help="Output format (default: txt)")
    
    # OpenVAS integration
    openvas_parser = subparsers.add_parser("openvas", help="Run OpenVAS integration")
    openvas_parser.add_argument("--host", required=True, help="GVM host")
    openvas_parser.add_argument("--port", type=int, default=9390, help="GVM port (default: 9390)")
    openvas_parser.add_argument("--username", default="admin", help="GVM username (default: admin)")
    openvas_parser.add_argument("--password", required=True, help="GVM password")
    openvas_parser.add_argument("-t", "--targets", required=True, help="Comma-separated list of targets to scan")
    openvas_parser.add_argument("-o", "--output", default="openvas_report", help="Output filename (without extension)")
    
    # Server
    server_parser = subparsers.add_parser("server", help="Run server")
    server_parser.add_argument("--host", default="0.0.0.0", help="Host to listen on (default: 0.0.0.0)")
    server_parser.add_argument("--port", type=int, default=8443, help="Port to listen on (default: 8443)")
    server_parser.add_argument("--generate-cert", action="store_true", help="Generate self-signed certificate")
    
    # Client
    client_parser = subparsers.add_parser("client", help="Run client")
    client_parser.add_argument("--host", required=True, help="Server host")
    client_parser.add_argument("--port", type=int, default=8443, help="Server port (default: 8443)")
    client_parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    
    # Traffic obfuscator
    obfuscate_parser = subparsers.add_parser("obfuscate", help="Run traffic obfuscator")
    obfuscate_parser.add_argument("type", choices=["http", "dns", "ssl", "custom"],
                                help="Obfuscation type")
    obfuscate_parser.add_argument("target", help="Target host")
    obfuscate_parser.add_argument("port", type=int, help="Target port")
    obfuscate_parser.add_argument("data", nargs="*", help="Data to send")
    
    return parser.parse_args()


def main():
    """Main function for the RavenTrace toolkit."""
    # Set up environment
    setup_environment()
    
    # Parse arguments
    args = parse_arguments()
    
    # Run appropriate module
    if args.command == "scan":
        run_port_scanner(sys.argv[2:])
    elif args.command == "discover":
        run_netdiscover_parser(sys.argv[2:])
    elif args.command == "openvas":
        run_openvas_integration(sys.argv[2:])
    elif args.command == "server":
        run_server(sys.argv[2:])
    elif args.command == "client":
        run_client(sys.argv[2:])
    elif args.command == "obfuscate":
        run_traffic_obfuscator(sys.argv[2:])
    else:
        logger.error("No command specified")
        sys.exit(1)


if __name__ == "__main__":
    main()
