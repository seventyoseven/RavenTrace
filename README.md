# RavenTrace - User Guide

## Overview

RavenTrace is a modular red team reconnaissance and remote operations toolkit written in Python. It provides a comprehensive set of tools for network scanning, host discovery, vulnerability assessment, and secure communications.

This guide covers installation, configuration, and usage of all RavenTrace modules.

## Table of Contents

1. [Installation](#installation)
2. [Project Structure](#project-structure)
3. [Port Scanner](#port-scanner)
4. [Netdiscover Parser](#netdiscover-parser)
5. [OpenVAS Integration](#openvas-integration)
6. [Traffic Obfuscator](#traffic-obfuscator)
7. [Command and Control](#command-and-control)
8. [Unified Launcher](#unified-launcher)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- OpenVAS/GVM (for vulnerability scanning features)
- netdiscover (for network discovery features)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/RavenTrace.git
   cd RavenTrace
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create necessary directories:
   ```
   mkdir -p certs results
   ```

## Project Structure

RavenTrace follows a modular architecture with each file performing a specific function:

```
RavenTrace/
│
├── client.py               # Remote client to receive and execute commands
├── server.py               # Server to send commands over SSL
├── port_scanner.py         # TCP port scanner
├── netdiscover_parser.py   # Parses netdiscover output to find live hosts
├── openvas_integration.py  # Triggers OpenVAS scans via the API
├── traffic_obfuscator.py   # HTTP/SSL traffic mimicry
├── main.py                 # Unified launcher
│
├── certs/
│   ├── server.crt          # SSL certificate
│   └── server.key          # SSL key
│
└── results/
    └── scan_report_*.txt   # Auto-generated scan results
```

## Port Scanner

The port scanner module (`port_scanner.py`) provides TCP port scanning capabilities with various scan types and options.

### Features

- Multiple scan types: Connect, SYN, NULL, FIN, XMAS
- Single host or network range scanning
- Port range or common ports scanning
- Randomization for evasion
- Detailed output formats

### Usage

#### Basic Scanning

Scan a single host for common ports:
```
python port_scanner.py -t 192.168.1.10 -c
```

Scan specific ports on a host:
```
python port_scanner.py -t 192.168.1.10 -p 22,80,443,8080
```

Scan a port range:
```
python port_scanner.py -t 192.168.1.10 -p 1-1024
```

#### Network Scanning

Scan an entire network:
```
python port_scanner.py -n 192.168.1.0/24 -c
```

#### Advanced Options

Use SYN scan (requires root privileges):
```
sudo python port_scanner.py -t 192.168.1.10 -s syn -p 1-1024
```

Add randomization and delay for evasion:
```
python port_scanner.py -t 192.168.1.10 --delay 0.5
```

Save results to a file:
```
python port_scanner.py -t 192.168.1.10 -o my_scan_results
```

### Command Line Options

```
usage: port_scanner.py [-h] (-t TARGET | -n NETWORK) [-p PORTS | -c] [-s {connect,syn,null,fin,xmas}]
                      [--timeout TIMEOUT] [--threads THREADS] [--delay DELAY] [--no-random]
                      [-o OUTPUT] [-v]

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target host to scan
  -n NETWORK, --network NETWORK
                        Target network to scan (CIDR notation)
  -p PORTS, --ports PORTS
                        Ports to scan (comma-separated or range, e.g., '80,443,8000-8100')
  -c, --common          Scan common ports only
  -s {connect,syn,null,fin,xmas}, --scan-type {connect,syn,null,fin,xmas}
                        Scan type (default: connect)
  --timeout TIMEOUT     Timeout for port connections in seconds (default: 1.0)
  --threads THREADS     Maximum number of concurrent threads (default: 100)
  --delay DELAY         Delay between port scans in seconds (default: 0.0)
  --no-random           Disable randomization of ports and hosts
  -o OUTPUT, --output OUTPUT
                        Output file for scan results
  -v, --verbose         Enable verbose output
```

## Netdiscover Parser

The netdiscover parser module (`netdiscover_parser.py`) processes output from the netdiscover tool to identify live hosts on a network.

### Features

- Parse netdiscover output files
- Run netdiscover directly from the module
- Resolve hostnames for discovered IPs
- Multiple output formats (TXT, CSV, JSON)
- MAC vendor identification

### Usage

#### Parsing Existing Output

Parse a netdiscover output file:
```
python netdiscover_parser.py -f netdiscover_output.txt
```

Save results in different formats:
```
python netdiscover_parser.py -f netdiscover_output.txt -o network_hosts -F json
```

#### Running Netdiscover

Run netdiscover on an interface:
```
sudo python netdiscover_parser.py -i eth0
```

Scan a specific IP range:
```
sudo python netdiscover_parser.py -i eth0 -r 192.168.1.0/24
```

#### Advanced Options

Resolve hostnames for discovered IPs:
```
python netdiscover_parser.py -f netdiscover_output.txt -n
```

Use a custom MAC vendor database:
```
python netdiscover_parser.py -f netdiscover_output.txt -m mac_vendors.txt
```

### Command Line Options

```
usage: netdiscover_parser.py [-h] (-f FILE | -i INTERFACE) [-r RANGE] [-c COUNT]
                            [-t TIMEOUT] [-o OUTPUT] [-F {txt,csv,json}]
                            [-m MAC_VENDORS] [-n]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Netdiscover output file to parse
  -i INTERFACE, --interface INTERFACE
                        Network interface to use for live scanning
  -r RANGE, --range RANGE
                        IP range to scan (CIDR notation)
  -c COUNT, --count COUNT
                        Number of discovery packets to send (default: 1)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds for live scanning (default: 30)
  -o OUTPUT, --output OUTPUT
                        Output filename (without extension)
  -F {txt,csv,json}, --format {txt,csv,json}
                        Output format (default: txt)
  -m MAC_VENDORS, --mac-vendors MAC_VENDORS
                        Path to MAC vendor database file
  -n, --resolve         Attempt to resolve hostnames
```

## OpenVAS Integration

The OpenVAS integration module (`openvas_integration.py`) provides an interface to the OpenVAS/GVM vulnerability scanner.

### Prerequisites

- OpenVAS/GVM installed and configured
- GVM credentials with appropriate permissions

### Features

- Trigger vulnerability scans via the GVM API
- Scan multiple targets
- Process and format scan results
- Multiple output formats (TXT, XML, JSON)

### Usage

#### Basic Scanning

Scan a single target:
```
python openvas_integration.py --host gvm.example.com --username admin --password secret -t 192.168.1.10
```

Scan multiple targets:
```
python openvas_integration.py --host gvm.example.com --username admin --password secret -t "192.168.1.10,192.168.1.20"
```

#### Output Options

Save results in different formats:
```
python openvas_integration.py --host gvm.example.com --username admin --password secret -t 192.168.1.10 -o vuln_scan -f json
```

#### Advanced Options

Use a custom scan configuration:
```
python openvas_integration.py --host gvm.example.com --username admin --password secret -t 192.168.1.10 --config "daba56c8-73ec-11df-a475-002264764cea"
```

Disable SSL verification (not recommended for production):
```
python openvas_integration.py --host gvm.example.com --username admin --password secret -t 192.168.1.10 --no-verify
```

### Command Line Options

```
usage: openvas_integration.py [-h] --host HOST [--port PORT] [--username USERNAME]
                             --password PASSWORD [--no-verify] -t TARGETS [-n NAME]
                             [--config CONFIG] [--timeout TIMEOUT] [--auto-delete]
                             [-o OUTPUT] [-f {json,xml,txt}]

options:
  -h, --help            show this help message and exit
  --host HOST           GVM host
  --port PORT           GVM port (default: 9390)
  --username USERNAME   GVM username (default: admin)
  --password PASSWORD   GVM password
  --no-verify           Disable SSL verification
  -t TARGETS, --targets TARGETS
                        Comma-separated list of targets to scan
  -n NAME, --name NAME  Name for the scan
  --config CONFIG       Scan config ID (default: Full and fast)
  --timeout TIMEOUT     API timeout in seconds (default: 300)
  --auto-delete         Auto-delete tasks after completion
  -o OUTPUT, --output OUTPUT
                        Output filename (without extension)
  -f {json,xml,txt}, --format {json,xml,txt}
                        Output format (default: txt)
```

## Traffic Obfuscator

The traffic obfuscator module (`traffic_obfuscator.py`) provides methods to obfuscate command and control traffic using various techniques.

### Features

- Multiple obfuscation methods: HTTP, DNS, SSL, Custom
- Strong encryption with AES-GCM
- Traffic randomization and jitter
- Retry mechanisms for reliability

### Usage

#### Basic Usage

Send data using HTTP obfuscation:
```
python traffic_obfuscator.py http example.com 80 "Hello, RavenTrace!"
```

Send data using DNS tunneling:
```
python traffic_obfuscator.py dns 8.8.8.8 53 "Hello, RavenTrace!"
```

Send data using SSL:
```
python traffic_obfuscator.py ssl example.com 443 "Hello, RavenTrace!"
```

Send data using custom protocol:
```
python traffic_obfuscator.py custom example.com 8443 "Hello, RavenTrace!"
```

### Command Line Options

```
usage: traffic_obfuscator.py <obfuscation_type> <target> <port> [data]

Obfuscation types: http, dns, ssl, custom
```

## Command and Control

RavenTrace includes a secure command and control system with a server (`server.py`) and client (`client.py`) component.

### Server

The server component manages client connections and sends commands to connected clients.

#### Features

- Secure SSL/TLS communication
- Client authentication
- Command queuing and result handling
- Self-signed certificate generation

#### Usage

Start the server with default options:
```
python server.py
```

Generate a self-signed certificate and start the server:
```
python server.py --generate-cert
```

Specify host and port:
```
python server.py --host 0.0.0.0 --port 8443
```

Enable client certificate authentication:
```
python server.py --client-auth --client-ca client_ca.crt
```

#### Command Line Options

```
usage: server.py [-h] [--host HOST] [--port PORT] [--cert CERT] [--key KEY]
                [--generate-cert] [--client-auth] [--client-ca CLIENT_CA]
                [--max-clients MAX_CLIENTS] [--timeout TIMEOUT] [--no-log-commands]
                [--log-file LOG_FILE]

options:
  -h, --help            show this help message and exit
  --host HOST           Host to listen on (default: 0.0.0.0)
  --port PORT           Port to listen on (default: 8443)
  --cert CERT           SSL certificate file (default: certs/server.crt)
  --key KEY             SSL key file (default: certs/server.key)
  --generate-cert       Generate self-signed certificate
  --client-auth         Require client certificate authentication
  --client-ca CLIENT_CA
                        Client CA certificate file for verification
  --max-clients MAX_CLIENTS
                        Maximum number of clients (default: 10)
  --timeout TIMEOUT     Client timeout in seconds (default: 30)
  --no-log-commands     Disable command logging
  --log-file LOG_FILE   Log file (default: raventrace_server.log)
```

### Client

The client component connects to the server and executes received commands.

#### Features

- Secure SSL/TLS communication
- Automatic reconnection
- Heartbeat mechanism
- Command execution with result reporting

#### Usage

Connect to a server:
```
python client.py --host server.example.com --port 8443
```

Connect with client certificate:
```
python client.py --host server.example.com --port 8443 --cert client.crt --key client.key
```

Disable SSL verification (not recommended for production):
```
python client.py --host server.example.com --port 8443 --no-verify
```

#### Command Line Options

```
usage: client.py [-h] --host HOST [--port PORT] [--cert CERT] [--key KEY]
                [--ca CA] [--no-verify] [--reconnect-interval RECONNECT_INTERVAL]
                [--max-reconnect MAX_RECONNECT]
                [--heartbeat-interval HEARTBEAT_INTERVAL] [--log-file LOG_FILE]

options:
  -h, --help            show this help message and exit
  --host HOST           Server host
  --port PORT           Server port (default: 8443)
  --cert CERT           Client certificate file
  --key KEY             Client key file
  --ca CA               CA certificate file
  --no-verify           Disable SSL verification
  --reconnect-interval RECONNECT_INTERVAL
                        Reconnect interval in seconds (default: 30)
  --max-reconnect MAX_RECONNECT
                        Maximum reconnect attempts (default: 10)
  --heartbeat-interval HEARTBEAT_INTERVAL
                        Heartbeat interval in seconds (default: 60)
  --log-file LOG_FILE   Log file (default: raventrace_client.log)
```

## Unified Launcher

The main module (`main.py`) provides a unified interface to all RavenTrace components.

### Usage

Run the port scanner:
```
python main.py scan -t 192.168.1.10 -p 80,443,8080
```

Run the netdiscover parser:
```
python main.py discover -f netdiscover_output.txt -o results
```

Run the OpenVAS integration:
```
python main.py openvas --host gvm.example.com --username admin --password secret -t 192.168.1.10
```

Start the server:
```
python main.py server --port 8443 --generate-cert
```

Start the client:
```
python main.py client --host server.example.com --port 8443
```

Use the traffic obfuscator:
```
python main.py obfuscate http example.com 80 "Test message"
```

### Command Line Options

```
usage: main.py [-h] {scan,discover,openvas,server,client,obfuscate} ...

RavenTrace - Modular Red Team Reconnaissance and Remote Operations Toolkit

positional arguments:
  {scan,discover,openvas,server,client,obfuscate}
                        Command to run
    scan                Run port scanner
    discover            Run netdiscover parser
    openvas             Run OpenVAS integration
    server              Run server
    client              Run client
    obfuscate           Run traffic obfuscator

options:
  -h, --help            show this help message and exit
```

## Security Considerations

RavenTrace is designed for educational and authorized security testing purposes only. When using this toolkit:

1. **Legal Compliance**: Only use on systems you own or have explicit permission to test.

2. **Network Impact**: Port scanning and network discovery can generate significant traffic. Use appropriate delays and limits.

3. **Secure Communications**: Always use SSL verification in production environments.

4. **Credential Security**: Protect API keys, passwords, and certificates used with the toolkit.

5. **Data Handling**: Securely store and handle any sensitive information discovered during scanning.

## Troubleshooting

### Common Issues

#### SSL Certificate Verification Failures

If you encounter SSL certificate verification issues:
- Ensure the server certificate is valid and trusted
- Use the `--ca` option to specify a CA certificate
- Only use `--no-verify` in testing environments

#### Connection Timeouts

If connections time out:
- Check network connectivity
- Verify firewall settings
- Increase timeout values

#### Permission Errors

For permission-related errors:
- Use `sudo` for operations requiring root privileges (SYN scans, network interface access)
- Check file permissions for certificates and output directories

### Logging

All modules write logs to their respective log files:
- `raventrace.log` - Main and general logs
- `raventrace_server.log` - Server logs
- `raventrace_client.log` - Client logs

Increase verbosity with the `-v` or `--verbose` option where available.

## Conclusion

RavenTrace provides a comprehensive set of tools for network reconnaissance and security testing. By following this guide, you should be able to effectively use all components of the toolkit for your authorized security testing needs.

Remember to always use these tools responsibly and ethically, with proper authorization and in compliance with all applicable laws and regulations.
