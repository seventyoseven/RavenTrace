#!/usr/bin/env python3
"""
RavenTrace - OpenVAS Integration Module

This module provides integration with OpenVAS vulnerability scanner,
allowing automated vulnerability scanning of discovered hosts and
processing of scan results.

Author: RavenTrace Team
Version: 1.0.0
License: Educational Use Only
"""

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
import xml.etree.ElementTree as ET

# For secure API communication
import requests
from requests.exceptions import RequestException
import urllib3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("raventrace.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("raventrace.openvas_integration")

# Disable insecure request warnings if using self-signed certificates
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class OpenVASConfig:
    """Configuration dataclass for OpenVAS integration."""
    gvm_host: str
    gvm_port: int = 9390
    gvm_username: str = "admin"
    gvm_password: str = ""
    verify_ssl: bool = True
    scan_config_id: str = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
    timeout: int = 300  # Timeout in seconds
    auto_delete: bool = False  # Auto-delete tasks after completion


class OpenVASIntegration:
    """
    Main class for OpenVAS integration in RavenTrace.
    
    This class provides methods to interact with OpenVAS/GVM via its API,
    create and manage scans, and process scan results.
    """
    
    def __init__(self, config: OpenVASConfig):
        """
        Initialize the OpenVAS integration with the given configuration.
        
        Args:
            config: OpenVAS configuration
        """
        self.config = config
        self.session = requests.Session()
        
        # Set up authentication
        self.session.auth = (config.gvm_username, config.gvm_password)
        
        # Set up SSL verification
        self.session.verify = config.verify_ssl
        
        # Base URL for API requests
        self.base_url = f"https://{config.gvm_host}:{config.gvm_port}/gmp"
        
        # Store task IDs
        self.tasks = {}
        
    def _make_request(self, command: str, params: Dict = None) -> ET.Element:
        """
        Make a request to the GVM API.
        
        Args:
            command: GMP command to execute
            params: Additional parameters for the command
            
        Returns:
            ET.Element: XML response as ElementTree
            
        Raises:
            Exception: If the request fails
        """
        if params is None:
            params = {}
            
        # Add command to parameters
        params['cmd'] = command
        
        try:
            # Make the request
            response = self.session.post(
                self.base_url,
                data=params,
                timeout=self.config.timeout
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.text)
            
            # Check for GMP errors
            status = root.get('status', '200')
            if status != '200':
                status_text = root.get('status_text', 'Unknown error')
                raise Exception(f"GMP error: {status} - {status_text}")
                
            return root
            
        except RequestException as e:
            logger.error(f"Request error: {e}")
            raise
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error making GMP request: {e}")
            raise
            
    def login(self) -> bool:
        """
        Authenticate with the GVM service.
        
        Returns:
            bool: True if login successful, False otherwise
        """
        try:
            # Make auth request
            response = self._make_request('authenticate')
            
            # Check if authentication was successful
            if response.get('status') == '200':
                logger.info("Successfully authenticated with GVM")
                return True
            else:
                logger.error("Authentication failed")
                return False
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
            
    def create_target(self, name: str, hosts: List[str]) -> Optional[str]:
        """
        Create a scan target.
        
        Args:
            name: Name for the target
            hosts: List of hosts to scan
            
        Returns:
            Optional[str]: Target ID if successful, None otherwise
        """
        try:
            # Join hosts into comma-separated string
            hosts_str = ','.join(hosts)
            
            # Create target
            response = self._make_request('create_target', {
                'name': name,
                'hosts': hosts_str,
                'port_list_id': 'c7e03b6c-3bbe-11e1-a057-406186ea4fc5'  # Default port list
            })
            
            # Extract target ID
            target_id = response.find('.//id')
            if target_id is not None:
                target_id = target_id.text
                logger.info(f"Created target '{name}' with ID {target_id}")
                return target_id
            else:
                logger.error("Failed to create target")
                return None
                
        except Exception as e:
            logger.error(f"Error creating target: {e}")
            return None
            
    def create_task(self, name: str, target_id: str) -> Optional[str]:
        """
        Create a scan task.
        
        Args:
            name: Name for the task
            target_id: Target ID to scan
            
        Returns:
            Optional[str]: Task ID if successful, None otherwise
        """
        try:
            # Create task
            response = self._make_request('create_task', {
                'name': name,
                'config_id': self.config.scan_config_id,
                'target_id': target_id,
                'scanner_id': '08b69003-5fc2-4037-a479-93b440211c73'  # OpenVAS scanner
            })
            
            # Extract task ID
            task_id = response.find('.//id')
            if task_id is not None:
                task_id = task_id.text
                logger.info(f"Created task '{name}' with ID {task_id}")
                self.tasks[name] = task_id
                return task_id
            else:
                logger.error("Failed to create task")
                return None
                
        except Exception as e:
            logger.error(f"Error creating task: {e}")
            return None
            
    def start_task(self, task_id: str) -> Optional[str]:
        """
        Start a scan task.
        
        Args:
            task_id: ID of the task to start
            
        Returns:
            Optional[str]: Report ID if successful, None otherwise
        """
        try:
            # Start task
            response = self._make_request('start_task', {
                'task_id': task_id
            })
            
            # Extract report ID
            report_id = response.find('.//report_id')
            if report_id is not None:
                report_id = report_id.text
                logger.info(f"Started task {task_id}, report ID: {report_id}")
                return report_id
            else:
                logger.error(f"Failed to start task {task_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error starting task: {e}")
            return None
            
    def get_task_status(self, task_id: str) -> str:
        """
        Get the status of a task.
        
        Args:
            task_id: ID of the task
            
        Returns:
            str: Task status
        """
        try:
            # Get task
            response = self._make_request('get_tasks', {
                'task_id': task_id
            })
            
            # Extract status
            status = response.find('.//status')
            if status is not None:
                return status.text
            else:
                return "Unknown"
                
        except Exception as e:
            logger.error(f"Error getting task status: {e}")
            return "Error"
            
    def wait_for_task(self, task_id: str, interval: int = 10) -> bool:
        """
        Wait for a task to complete.
        
        Args:
            task_id: ID of the task
            interval: Polling interval in seconds
            
        Returns:
            bool: True if task completed successfully, False otherwise
        """
        logger.info(f"Waiting for task {task_id} to complete...")
        
        while True:
            status = self.get_task_status(task_id)
            
            if status == "Done":
                logger.info(f"Task {task_id} completed successfully")
                return True
            elif status in ["Stopped", "Failed"]:
                logger.error(f"Task {task_id} {status.lower()}")
                return False
                
            logger.info(f"Task {task_id} status: {status}")
            time.sleep(interval)
            
    def get_report(self, report_id: str, format_id: str = "a994b278-1f62-11e1-96ac-406186ea4fc5") -> Optional[str]:
        """
        Get a report.
        
        Args:
            report_id: ID of the report
            format_id: Format ID for the report (default: XML)
            
        Returns:
            Optional[str]: Report content if successful, None otherwise
        """
        try:
            # Get report
            response = self._make_request('get_reports', {
                'report_id': report_id,
                'format_id': format_id
            })
            
            # Extract report
            report = response.find('.//report')
            if report is not None:
                # Convert report element to string
                report_str = ET.tostring(report, encoding='unicode')
                logger.info(f"Retrieved report {report_id}")
                return report_str
            else:
                logger.error(f"Failed to retrieve report {report_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting report: {e}")
            return None
            
    def delete_task(self, task_id: str) -> bool:
        """
        Delete a task.
        
        Args:
            task_id: ID of the task
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Delete task
            response = self._make_request('delete_task', {
                'task_id': task_id
            })
            
            # Check status
            if response.get('status') == '200':
                logger.info(f"Deleted task {task_id}")
                return True
            else:
                logger.error(f"Failed to delete task {task_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting task: {e}")
            return False
            
    def scan_hosts(self, hosts: List[str], name: str = None) -> Optional[str]:
        """
        Scan a list of hosts.
        
        Args:
            hosts: List of hosts to scan
            name: Name for the scan (optional)
            
        Returns:
            Optional[str]: Report ID if successful, None otherwise
        """
        if not hosts:
            logger.error("No hosts provided for scanning")
            return None
            
        # Generate name if not provided
        if name is None:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            name = f"RavenTrace-Scan-{timestamp}"
            
        try:
            # Login
            if not self.login():
                return None
                
            # Create target
            target_id = self.create_target(f"{name}-Target", hosts)
            if not target_id:
                return None
                
            # Create task
            task_id = self.create_task(name, target_id)
            if not task_id:
                return None
                
            # Start task
            report_id = self.start_task(task_id)
            if not report_id:
                return None
                
            # Wait for task to complete
            if not self.wait_for_task(task_id):
                return None
                
            # Auto-delete task if configured
            if self.config.auto_delete:
                self.delete_task(task_id)
                
            return report_id
            
        except Exception as e:
            logger.error(f"Error scanning hosts: {e}")
            return None
            
    def parse_report(self, report_xml: str) -> Dict:
        """
        Parse a report XML into a structured format.
        
        Args:
            report_xml: Report XML content
            
        Returns:
            Dict: Structured report data
        """
        try:
            # Parse XML
            root = ET.fromstring(report_xml)
            
            # Extract basic information
            report_data = {
                'scan_start': root.findtext('.//scan_start') or '',
                'scan_end': root.findtext('.//scan_end') or '',
                'hosts': [],
                'vulnerabilities': []
            }
            
            # Extract hosts
            for host in root.findall('.//host'):
                host_data = {
                    'ip': host.findtext('ip') or '',
                    'hostname': host.findtext('hostname') or '',
                    'os': host.findtext('os') or '',
                    'ports': []
                }
                
                # Extract ports
                for port in host.findall('.//port'):
                    port_data = {
                        'port': port.text or '',
                        'protocol': port.get('protocol', ''),
                        'service': port.findtext('service') or ''
                    }
                    host_data['ports'].append(port_data)
                    
                report_data['hosts'].append(host_data)
                
            # Extract vulnerabilities
            for result in root.findall('.//result'):
                vuln_data = {
                    'name': result.findtext('name') or '',
                    'host': result.findtext('host') or '',
                    'port': result.findtext('port') or '',
                    'severity': result.findtext('severity') or '',
                    'description': result.findtext('description') or '',
                    'solution': result.findtext('solution') or ''
                }
                report_data['vulnerabilities'].append(vuln_data)
                
            return report_data
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return {}
        except Exception as e:
            logger.error(f"Error parsing report: {e}")
            return {}
            
    def save_report(self, report_id: str, filename: str, format: str = 'json') -> bool:
        """
        Save a report to a file.
        
        Args:
            report_id: ID of the rep
(Content truncated due to size limit. Use line ranges to read in chunks)