#!/usr/bin/env python3
"""
RavenTrace - Server Module

This module implements a secure command and control server for RavenTrace,
allowing secure communication with clients over SSL/TLS with proper
authentication and encryption.

Author: RavenTrace Team
Version: 1.0.0
License: Educational Use Only
"""

import argparse
import json
import logging
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("raventrace_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("raventrace.server")


@dataclass
class ServerConfig:
    """Configuration dataclass for the RavenTrace server."""
    host: str = "0.0.0.0"
    port: int = 8443
    cert_file: str = "certs/server.crt"
    key_file: str = "certs/server.key"
    client_auth: bool = False
    client_ca_file: Optional[str] = None
    max_clients: int = 10
    timeout: int = 30
    log_commands: bool = True
    log_file: str = "raventrace_server.log"


class ClientHandler:
    """
    Handler for client connections.
    
    This class manages communication with a connected client,
    handling authentication, command execution, and results.
    """
    
    def __init__(self, client_socket: ssl.SSLSocket, address: Tuple[str, int], 
                server: 'RavenTraceServer'):
        """
        Initialize the client handler.
        
        Args:
            client_socket: The client's SSL socket
            address: The client's address (host, port)
            server: The parent server instance
        """
        self.socket = client_socket
        self.address = address
        self.server = server
        self.client_id = str(uuid.uuid4())
        self.authenticated = False
        self.hostname = None
        self.username = None
        self.os_info = None
        self.last_seen = datetime.now()
        self.running = True
        
    def handle(self) -> None:
        """Handle the client connection."""
        try:
            logger.info(f"New connection from {self.address[0]}:{self.address[1]}")
            
            # Set socket timeout
            self.socket.settimeout(self.server.config.timeout)
            
            # Perform authentication
            if not self._authenticate():
                logger.warning(f"Authentication failed for {self.address[0]}")
                return
                
            # Main communication loop
            while self.running:
                # Receive command from server
                command = self.server.get_next_command(self)
                
                if not command:
                    # No command available, sleep briefly
                    time.sleep(0.1)
                    continue
                    
                # Send command to client
                if not self._send_command(command):
                    break
                    
                # Receive result from client
                result = self._receive_result()
                
                if not result:
                    break
                    
                # Process result
                self._process_result(command, result)
                
        except (socket.timeout, ConnectionResetError, BrokenPipeError) as e:
            logger.info(f"Client {self.client_id} disconnected: {e}")
        except Exception as e:
            logger.error(f"Error handling client {self.client_id}: {e}")
        finally:
            # Clean up
            self._cleanup()
            
    def _authenticate(self) -> bool:
        """
        Authenticate the client.
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        try:
            # Send authentication challenge
            challenge = os.urandom(32).hex()
            self._send_message({
                "type": "auth_challenge",
                "challenge": challenge
            })
            
            # Receive authentication response
            response = self._receive_message()
            
            if not response or response.get("type") != "auth_response":
                logger.warning(f"Invalid authentication response from {self.address[0]}")
                return False
                
            # Extract client information
            self.hostname = response.get("hostname")
            self.username = response.get("username")
            self.os_info = response.get("os_info")
            
            # Verify response (in a real implementation, this would use proper cryptographic verification)
            # For this educational version, we'll accept any response with the required fields
            if self.hostname and self.username and self.os_info:
                self.authenticated = True
                self.last_seen = datetime.now()
                
                # Register with server
                self.server.register_client(self)
                
                # Send authentication success
                self._send_message({
                    "type": "auth_result",
                    "success": True,
                    "client_id": self.client_id
                })
                
                logger.info(f"Client {self.client_id} authenticated: {self.username}@{self.hostname} ({self.os_info})")
                return True
            else:
                # Send authentication failure
                self._send_message({
                    "type": "auth_result",
                    "success": False,
                    "message": "Missing required information"
                })
                
                logger.warning(f"Authentication failed for {self.address[0]}: Missing required information")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
            
    def _send_command(self, command: Dict) -> bool:
        """
        Send a command to the client.
        
        Args:
            command: The command to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Log command if enabled
            if self.server.config.log_commands:
                logger.info(f"Sending command to {self.client_id}: {command.get('command')}")
                
            # Send command
            return self._send_message(command)
            
        except Exception as e:
            logger.error(f"Error sending command to {self.client_id}: {e}")
            return False
            
    def _receive_result(self) -> Optional[Dict]:
        """
        Receive a command result from the client.
        
        Returns:
            Optional[Dict]: The result or None if error
        """
        try:
            # Receive result
            result = self._receive_message()
            
            if not result:
                return None
                
            # Update last seen time
            self.last_seen = datetime.now()
            
            # Log result if enabled
            if self.server.config.log_commands:
                logger.info(f"Received result from {self.client_id}: {result.get('status', 'unknown')}")
                
            return result
            
        except Exception as e:
            logger.error(f"Error receiving result from {self.client_id}: {e}")
            return None
            
    def _process_result(self, command: Dict, result: Dict) -> None:
        """
        Process a command result.
        
        Args:
            command: The original command
            result: The command result
        """
        # Store result in server
        self.server.store_result(self, command, result)
        
    def _send_message(self, message: Dict) -> bool:
        """
        Send a message to the client.
        
        Args:
            message: The message to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Convert message to JSON
            message_json = json.dumps(message)
            
            # Add message length prefix
            message_bytes = message_json.encode('utf-8')
            length_prefix = len(message_bytes).to_bytes(4, byteorder='big')
            
            # Send length prefix and message
            self.socket.sendall(length_prefix + message_bytes)
            return True
            
        except Exception as e:
            logger.error(f"Error sending message to {self.client_id}: {e}")
            return False
            
    def _receive_message(self) -> Optional[Dict]:
        """
        Receive a message from the client.
        
        Returns:
            Optional[Dict]: The received message or None if error
        """
        try:
            # Receive message length
            length_prefix = self.socket.recv(4)
            if not length_prefix or len(length_prefix) < 4:
                logger.warning(f"Connection closed by {self.client_id}")
                return None
                
            # Parse message length
            message_length = int.from_bytes(length_prefix, byteorder='big')
            
            # Sanity check on length
            if message_length > 10485760:  # 10MB max
                logger.warning(f"Message too large from {self.client_id}: {message_length} bytes")
                return None
                
            # Receive message data
            message_data = b""
            bytes_received = 0
            
            while bytes_received < message_length:
                chunk = self.socket.recv(min(4096, message_length - bytes_received))
                if not chunk:
                    logger.warning(f"Connection closed by {self.client_id} during message receive")
                    return None
                    
                message_data += chunk
                bytes_received += len(chunk)
                
            # Parse JSON message
            message_json = message_data.decode('utf-8')
            return json.loads(message_json)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from {self.client_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error receiving message from {self.client_id}: {e}")
            return None
            
    def _cleanup(self) -> None:
        """Clean up the client connection."""
        try:
            # Close socket
            self.socket.close()
            
            # Unregister from server
            self.server.unregister_client(self)
            
            logger.info(f"Client {self.client_id} disconnected")
            
        except Exception as e:
            logger.error(f"Error cleaning up client {self.client_id}: {e}")
            
    def send_command_and_wait(self, command: Dict, timeout: int = 60) -> Optional[Dict]:
        """
        Send a command to the client and wait for the result.
        
        Args:
            command: The command to send
            timeout: Timeout in seconds
            
        Returns:
            Optional[Dict]: The command result or None if timeout/error
        """
        # Generate command ID
        command_id = str(uuid.uuid4())
        command["id"] = command_id
        
        # Create result event
        result_event = threading.Event()
        result_container = {"result": None}
        
        # Register result callback
        def result_callback(result):
            result_container["result"] = result
            result_event.set()
            
        self.server.register_result_callback(command_id, result_callback)
        
        try:
            # Send command
            if not self._send_command(command):
                return None
                
            # Wait for result
            if result_event.wait(timeout):
                return result_container["result"]
            else:
                logger.warning(f"Command {command_id} timed out for client {self.client_id}")
                return None
                
        finally:
            # Unregister callback
            self.server.unregister_result_callback(command_id)


class RavenTraceServer:
    """
    Main server class for RavenTrace.
    
    This class implements a secure command and control server,
    managing client connections and command execution.
    """
    
    def __init__(self, config: ServerConfig):
        """
        Initialize the server with the given configuration.
        
        Args:
            config: Server configuration
        """
        self.config = config
        self.socket = None
        self.ssl_context = None
        self.running = False
        self.clients = {}
        self.clients_lock = threading.Lock()
        self.command_queue = []
        self.command_queue_lock = threading.Lock()
        self.results = {}
        self.results_lock = threading.Lock()
        self.result_callbacks = {}
        self.result_callbacks_lock = threading.Lock()
        
    def start(self) -> None:
        """Start the server."""
        try:
            # Create SSL context
            self.ssl_context = self._create_ssl_context()
            
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind socket
            self.socket.bind((self.config.host, self.config.port))
            
            # Listen for connections
            self.socket.listen(self.config.max_clients)
            
            logger.info(f"Server started on {self.config.host}:{self.config.port}")
            
            # Set running flag
            self.running = True
            
            # Accept connections
            while self.running:
                try:
                    # Accept connection
                    client_socket, address = self.socket.accept()
                    
                    # Wrap with SSL
                    ssl_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    
                    # Create client handler
                    handler = ClientHandler(ssl_socket, address, self)
                    
                    # Start handler thread
                    thread = threading.Thread(target=handler.handle)
                    thread.daemon = True
                    thread.start()
                    
                except KeyboardInterrupt:
                    logger.info("Server stopping...")
                    self.running = False
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            logger.error(f"Error starting server: {e}")
        finally:
            self._cleanup()
            
    def stop(self) -> None:
        """Stop the server."""
        logger.info("Stopping server...")
        self.running = False
        self._cleanup()
        
    def _cleanup(self) -> None:
        """Clean up server resources."""
        try:
            # Close all client connections
            with self.clients_lock:
                for client_id, client in list(self.clients.items()):
                    try:
                        client.socket.close()
                    except Exception:
                        pass
                        
                self.clients.clear()
                
            # Close server socket
            if self.socket:
                self.socket.close()
                self.socket = None
                
            logger.info("Server stopped")
            
        except Exception as e:
            logger.error(f"Error cleaning up server: {e}")
            
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create an SSL context for the server.
        
        Returns:
            ssl.SSLContext: The SSL context
        """
        try:
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Load certificate and key
            context.load_cert_chain(certfile=self.config.cert_file, keyfile=self.config.key_file)
            
            # Configure security options
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
            
            # Enable client certificate verification if configured
            if self.config.client_auth:
                context.verify_mode = ssl.CERT_REQUIRED
                
                if self.config.client_ca_file:
                    context.load_verify_locations(cafile=self.config.client_ca_file)
                    
            return context
            
        except Exception as e:
            logger.error(f"Error creating SSL context: {e}")
            raise
            
    def register_client(self, client: ClientHandler) -> None:
        """
        Register a client with the server.
        
        Args:
            client: The client handler to register
        """
        with self.clients_lock:
            self.clients[client.client_id] = client
            
    def unregister_client(self, client: ClientHandler) -> None:
        """
        Unregister a client from the server.
        
        Args:
            client: The client handler to unregister
        """
        with self.clients_lock:
            if client.client_id in self.clients:
                del self.clients[client.client_id]
                
    def get_clients(self) -> List[Dict]:
        """
        Get a list of connected clients.
        
        Returns:
            List[Dict]: List of client information
        """
        clients_info = []
        
        with self.clients_lock:
            for client_id, client in self.clients.items():
                clients_info.append({
                    "id": client_id,
                    "hostname": client.hostname,
                    "username": client.username,
                    "os_info": client.os_info,
                    "address": f"{client.address[0]}:{client.address[1]}",
                    "last_seen": client.last_seen.isoformat()
                })
                
        return clients_info
        
    def get_client_by_id(self, client_id: str) -> Optional[ClientHandler]:
        """
        Get a client by ID.
        
        Args:
            client_id: The client ID
            
        Returns:
            Optional[ClientHandler]: The client handler or None if not found
        """
        with self.clients_lock:
            return self.clients.get(client_id)
            
    def queue_command(self, command: Dict, client_id: Optional[str] = None) -> None:
        """
        Queue a command for execution.
        
        Args:
            command: The command to queue
            client_id: The target client ID (None for all clients)
        """
        with self.command_queue_lock:
            # Add command to queue
            self.command_queue.append({
                "command": command,
                "client_id": client_id,
                "timestamp": datetime.now()
            })
            
    def get_next_command(self, client: ClientHandler) -> Optional[Dict]:
        """
        Get the next command for a client.
        
        Args:
            client: The client handler
            
        Returns:
            Optional[Dict]: The next command or None if no commands
        """
        with self.command_queue_lock:
            # Find commands for this client
            for i, item in enumerate(self.command_queue):
                if item["client_id"] is None or item["client_id"] == client.client_id:
                    # Remove command from queue
                    command = self.command_queue.pop(i)
                    return command["command"]
                    
        return None
        
    def store_result(self, client: ClientHandler, command: Dict, result: Dict) -> None:
        """
        Store a command result.
        
        Args:
            client: The client handler
            command: The original command
            result: The command result
        """
        # Add client and timestamp information
        result["client_id"] = client.client_id
        result["timestamp"] = datetime.now().isoformat()
        
        # Get command ID
        command_id = command.get("id")
        
        if command_id:
            # Check for result callback
            with self.result_callbacks_lock:
                callback = self.result_callbacks.get(command_id)
                if callback:
                    callback(result)
                    
        # Store result
        with self.results_lock:
            if client.client_id not in self.results:
                self.results[client.client_id] = []
                
            self.results[client.client_id].append({
                "command": command,
                "result": result,
                "timestamp": datetime.now()
            })
            
    def register_result_callback(self, command_id: str, callback: Callable) -> None:
        """
        Register a callback for a command result.
        
        Args:
            command_id: The command ID
            callback: The callback function
        """
        with self.result_callbacks_lock:
            self.result_callbacks[command_id] = callback
            
    def unregister_result_callback(self, command_id: str) -> None:
        """
        Unregister a result callback.
        
        Args:
            command_id: The command ID
        """
        with self.result_callbacks_lock:
            if command_id in self.result_callbacks:
                del self.result_callbacks[command_id]
                
    def get_results(self, client_id: Optional[str] = None) -> List[Dict]:
        """
        Get command results.
        
        Args:
            client_id: The client ID (None for all clients)
            
        Returns:
            List[Dict]: List of command results
        """
        results = []
        
        with self.results_lock:
            if client_id:
                # Get results for specific client
                client_results = self.results.get(client_id, [])
                results.extend(client_results)
            else:
                # Get results for all clients
                for client_results in self.results.values():
                    results.extend(client_results)
                    
        # Sort by timestamp
        results.sort(key=lambda r: r["timestamp"])
        
        return results
        
    def clear_results(self, client_id: Optional[str] = None) -> None:
        """
        Clear command results.
        
        Args:
            client_id: The client ID (None for all clients)
        """
        with self.results_lock:
            if client_id:
                # Clear results for specific client
                if client_id in self.results:
                    self.results[client_id] = []
            else:
                # Clear all results
                self.results.clear()
                
    def execute_command(self, command: Dict, client_id: str, timeout: int = 60) -> Optional[Dict]:
        """
        Execute a command on a client and wait for the result.
        
        Args:
            command: The command to execute
            client_id: The target client ID
            timeout: Timeout in seconds
            
        Returns:
            Optional[Dict]: The command result or None if timeout/error
        """
        # Get client
        client = self.get_client_by_id(client_id)
        if not client:
            logger.error(f"Client not found: {client_id}")
            return None
            
        # Execute command
        return client.send_command_and_wait(command, timeout)


def generate_self_signed_cert(cert_file: str, key_file: str) -> bool:
    """
    Generate a self-signed SSL certificate.
    
    Args:
        cert_file: Output certificate file
        key_file: Output key file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
        
        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RavenTrace"),
            x509.NameAttribute(NameOID.COMMON_NAME, "raventrace.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False
        ).sign(key, hashes.SHA256())
        
        # Create certs directory if it doesn't exist
        certs_dir = Path("certs")
        certs_dir.mkdir(exist_ok=True)
        
        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        # Write key
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        logger.info(f"Generated self-signed certificate: {cert_file}, {key_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error generating self-signed certificate: {e}")
        return False


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="RavenTrace Server")
    
    # Server options
    parser.add_argument("--host", default="0.0.0.0", help="Host to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8443, help="Port to listen on (default: 8443)")
    
    # SSL options
    parser.add_argument("--cert", default="certs/server.crt", help="SSL certificate file (default: certs/server.crt)")
    parser.add_argument("--key", default="certs/server.key", help="SSL key file (default: certs/server.key)")
    parser.add_argument("--generate-cert", action="store_true", help="Generate self-signed certificate")
    parser.add_argument("--client-auth", action="store_true", help="Require client certificate authentication")
    parser.add_argument("--client-ca", help="Client CA certificate file for verification")
    
    # Other options
    parser.add_argument("--max-clients", type=int, default=10, help="Maximum number of clients (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Client timeout in seconds (default: 30)")
    parser.add_argument("--no-log-commands", action="store_true", help="Disable command logging")
    parser.add_argument("--log-file", default="raventrace_server.log", help="Log file (default: raventrace_server.log)")
    
    return parser.parse_args()


def main():
    """Main function for the server."""
    args = parse_arguments()
    
    # Generate certificate if requested
    if args.generate_cert:
        if not generate_self_signed_cert(args.cert, args.key):
            sys.exit(1)
            
    # Create configuration
    config = ServerConfig(
        host=args.host,
        port=args.port,
        cert_file=args.cert,
        key_file=args.key,
        client_auth=args.client_auth,
        client_ca_file=args.client_ca,
        max_clients=args.max_clients,
        timeout=args.timeout,
        log_commands=not args.no_log_commands,
        log_file=args.log_file
    )
    
    # Create server
    server = RavenTraceServer(config)
    
    try:
        # Start server
        server.start()
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    finally:
        # Stop server
        server.stop()


if __name__ == "__main__":
    main()
