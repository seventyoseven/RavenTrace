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
                
            # Clo
(Content truncated due to size limit. Use line ranges to read in chunks)