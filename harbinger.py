#!/usr/bin/env python3
"""
Harbinger - Network Host Monitoring Tool
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

Monitors hosts for pre-defined open TCP ports using SQLite3 database.
Generates email reports when new hosts are detected.
"""

import argparse
import sqlite3
import subprocess
import smtplib
import yaml
import logging
import time
import threading
import os
import platform
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import re
import schedule


class HarbingerMonitor:
    def __init__(self, config_file='harbinger.yaml'):
        self.config_file = config_file
        self.config = self.load_config()
        self.db_file = 'harbinger.db'
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == 'windows'
        self.setup_logging()
        self.setup_database()
        self.check_dependencies()
        
    def load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.error(f"Configuration file {self.config_file} not found")
            raise
        except yaml.YAMLError as e:
            logging.error(f"Error parsing configuration file: {e}")
            raise
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('logging', {}).get('level', 'INFO')
        log_file = self.config.get('logging', {}).get('file', 'harbinger.log')
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        logging.info("Harbinger logging initialized")
    
    def setup_database(self):
        """Initialize SQLite database and create tables for each port"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Get all configured ports
            ports = []
            for section_name, section_data in self.config.items():
                if section_name.startswith('port_'):
                    port = section_data.get('port')
                    if port:
                        ports.append(port)
            
            # Create table for each port
            for port in ports:
                table_name = f"hosts_port_{port}"
                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS {table_name} (
                        ip_address TEXT PRIMARY KEY,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL
                    )
                """)
            
            conn.commit()
            conn.close()
            logging.info(f"Database initialized with tables for ports: {ports}")
            
        except sqlite3.Error as e:
            logging.error(f"Database setup error: {e}")
            raise
    
    def check_dependencies(self):
        """Check if required dependencies are available"""
        logging.info(f"Running on {self.os_type} platform")
        
        # Check for nmap
        try:
            result = subprocess.run(
                ['nmap', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                logging.info("Nmap is available")
            else:
                logging.warning("Nmap may not be properly installed or accessible")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logging.warning("Nmap not found - only custom commands will work")
    
    def execute_command(self, command, port=None):
        """Execute a shell command and return stdout as list of IP addresses"""
        try:
            # Substitute {port} placeholder if provided
            if port is not None:
                command = command.replace('{port}', str(port))
            
            # Use platform-appropriate shell execution
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=300,  # 5 minute timeout
                encoding='utf-8',
                errors='replace'  # Handle encoding issues gracefully
            )
            
            if result.returncode != 0:
                error_msg = f"Command failed with return code {result.returncode}: {command}"
                if result.stderr:
                    error_msg += f" - {result.stderr.strip()}"
                raise Exception(error_msg)
            
            # Parse IP addresses from output
            ip_addresses = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and self.is_valid_ip(line):
                    ip_addresses.append(line)
                # Also look for IPs within lines that might have other text
                elif line:
                    # Extract IP addresses from lines that contain other text
                    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    for ip in ip_matches:
                        if self.is_valid_ip(ip):
                            ip_addresses.append(ip)
            
            # Remove duplicates while preserving order
            unique_ips = list(dict.fromkeys(ip_addresses))
            
            logging.info(f"Command '{command}' found {len(unique_ips)} IP addresses")
            return unique_ips
            
        except subprocess.TimeoutExpired:
            logging.error(f"Command timed out: {command}")
            return []
        except Exception as e:
            # Re-raise command failures so they can be handled by scan_ports
            if "Command failed with return code" in str(e):
                raise
            logging.error(f"Error executing command '{command}': {e}")
            return []
    
    def nmap_scan(self, nmap_args, port):
        """Perform nmap scan using provided arguments with port substitution"""
        try:
            # Substitute {port} placeholder in nmap arguments
            command = nmap_args.replace('{port}', str(port))
            
            # Use platform-appropriate shell execution
            shell = True if os.name == 'nt' else True
            result = subprocess.run(
                command, 
                shell=shell, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logging.error(f"Nmap scan failed with return code {result.returncode}")
                logging.error(f"Error output: {result.stderr}")
                return []
            
            # Parse IP addresses from nmap output
            ip_addresses = []
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                # Handle different nmap output formats
                if 'Nmap scan report for' in line:
                    # Extract IP address from various formats:
                    # "Nmap scan report for 10.0.0.1"
                    # "Nmap scan report for hostname (10.0.0.1)"
                    # "Nmap scan report for 10.0.0.1 (10.0.0.1)"
                    parts = line.split()
                    for part in parts:
                        # Clean up parentheses and other characters
                        clean_part = part.strip('()')
                        if self.is_valid_ip(clean_part):
                            ip_addresses.append(clean_part)
                            break
            
            logging.info(f"Nmap scan found {len(ip_addresses)} hosts")
            return ip_addresses
            
        except subprocess.TimeoutExpired:
            logging.error(f"Nmap scan timed out: {command}")
            return []
        except Exception as e:
            logging.error(f"Nmap scan error: {e}")
            return []
    
    def is_valid_ip(self, ip_string):
        """Validate IP address format"""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(ip_pattern, ip_string) is not None
    
    def update_host_database(self, port, ip_addresses):
        """Update database with new host information"""
        if not ip_addresses:
            return []
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        table_name = f"hosts_port_{port}"
        new_hosts = []
        current_time = datetime.now().isoformat()
        
        try:
            for ip in ip_addresses:
                # Check if host exists
                cursor.execute(f"SELECT ip_address FROM {table_name} WHERE ip_address = ?", (ip,))
                existing = cursor.fetchone()
                
                if existing:
                    # Update last_seen
                    cursor.execute(
                        f"UPDATE {table_name} SET last_seen = ? WHERE ip_address = ?",
                        (current_time, ip)
                    )
                else:
                    # New host detected
                    cursor.execute(
                        f"INSERT INTO {table_name} (ip_address, first_seen, last_seen) VALUES (?, ?, ?)",
                        (ip, current_time, current_time)
                    )
                    new_hosts.append(ip)
                    logging.info(f"New host detected: {ip} on port {port}")
            
            conn.commit()
            return new_hosts
            
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return []
        finally:
            conn.close()
    
    def generate_report(self, email_address, port_data, label=None):
        """Generate email report for new hosts"""
        total_new_hosts = 0
        total_errors = 0
        formatted_content = []
        
        # Process each port's data
        for port, data in port_data.items():
            hosts = data.get('hosts', [])
            error = data.get('error')
            
            # Get port_label and post_command from config for this port
            port_label = self.get_port_port_label(port)
            post_command = self.get_port_post_command(port)
            
            if port_label:
                port_header = f"Port {port} ({port_label}):"
            else:
                port_header = f"Port {port}:"
            
            if error:
                # Scan failed
                total_errors += 1
                formatted_content.append(f"\n{port_header}\n")
                formatted_content.append(f"[SCAN FAILED: {error}]\n")
            elif hosts:
                # New hosts found
                total_new_hosts += len(hosts)
                formatted_content.append(f"\n{port_header}\n")
                
                for host in hosts:
                    formatted_content.append(f"{host}\n")
                    
                    # Execute post_command if configured
                    if post_command:
                        command_output = self.execute_post_command(post_command, host, port)
                        if command_output:
                            formatted_content.append(f"{command_output}\n")
                        formatted_content.append("\n")  # Add blank line after command output
            else:
                # No new hosts found (scan successful)
                formatted_content.append(f"\n{port_header}\n")
                formatted_content.append("No new hosts detected.\n")
        
        # Determine subject and report type
        if total_errors > 0 and total_new_hosts == 0:
            subject = f"Harbinger Report for {label}: Scan failures detected"
        elif total_new_hosts > 0 and total_errors > 0:
            subject = f"Harbinger Report for {label}: {total_new_hosts} new hosts detected, {total_errors} scan failures"
        elif total_new_hosts > 0:
            subject = f"Harbinger Report for {label}: {total_new_hosts} new host{'s' if total_new_hosts != 1 else ''} detected"
        else:
            subject = f"Harbinger Report for {label}: No new hosts detected"
        
        # Generate report body
        body = f"""Harbinger Network Monitoring Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

New hosts detected: {total_new_hosts}
Scan failures: {total_errors}

Details:
{''.join(formatted_content)}

This report was generated by Harbinger monitoring tool.
"""
        
        # Only send email if email_address is provided
        if email_address:
            self.send_email(email_address, subject, body)
        
        # Always save report to file
        self.save_report_to_file(label, subject, body)
        
        if total_new_hosts > 0:
            if email_address:
                logging.info(f"Sent report to {email_address} with {total_new_hosts} new hosts")
            else:
                logging.info(f"Generated report for {label} with {total_new_hosts} new hosts (report only)")
        elif total_errors > 0:
            if email_address:
                logging.info(f"Sent report to {email_address} with {total_errors} scan failures")
            else:
                logging.info(f"Generated report for {label} with {total_errors} scan failures (report only)")
        else:
            if email_address:
                logging.info(f"Sent 'no new hosts' report to {email_address}")
            else:
                logging.info(f"Generated 'no new hosts' report for {label} (report only)")
    
    def send_email(self, to_address, subject, body):
        """Send email using SMTP or local mail command"""
        email_config = self.config.get('email', {})
        
        # Check if local mail is enabled
        if email_config.get('use_local_mail', False):
            try:
                mail_cmd = email_config.get('mail_command', 'mail')
                
                # Construct command as string to properly handle spaces in subject
                # Format: mail -s "subject" recipient
                cmd = f'{mail_cmd} -s "{subject}" {to_address}'
                
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(input=body)
                
                if process.returncode == 0:
                    logging.info(f"Sent local mail to {to_address} using '{mail_cmd}'")
                else:
                    logging.error(f"Failed to send local mail to {to_address}: {stderr}")
                    
            except Exception as e:
                logging.error(f"Failed to send local mail to {to_address}: {e}")
        else:
            # Original SMTP method
            try:
                msg = MIMEMultipart()
                msg['From'] = email_config.get('from_address')
                msg['To'] = to_address
                msg['Subject'] = subject
                
                msg.attach(MIMEText(body, 'plain'))
                
                with smtplib.SMTP(email_config.get('smtp_server'), email_config.get('smtp_port', 587)) as server:
                    if email_config.get('use_tls', True):
                        server.starttls()
                    
                    if email_config.get('username') and email_config.get('password'):
                        server.login(email_config.get('username'), email_config.get('password'))
                    
                    server.send_message(msg)
                    
            except Exception as e:
                logging.error(f"Failed to send email to {to_address}: {e}")
    
    def save_report_to_file(self, label, subject, body):
        """Save report to timestamped file"""
        try:
            # Check if file reports are enabled
            if not self.config.get('reports', {}).get('save_to_file', False):
                return
            
            # Create reports directory if it doesn't exist
            reports_dir = self.config.get('reports', {}).get('directory', 'reports')
            Path(reports_dir).mkdir(exist_ok=True)
            
            # Generate timestamped filename using label
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            # Convert spaces to underscores in label for filename
            safe_label = label.replace(' ', '_')
            filename = f"{reports_dir}/{safe_label}_{timestamp}.txt"
            
            # Create report content
            report_content = f"""HARBINGER NETWORK MONITORING REPORT
=====================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Label: {label}
Subject: {subject}

{body}

Report saved: {datetime.now().isoformat()}
"""
            
            # Write to file
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            logging.info(f"Report saved to file: {filename}")
            
        except Exception as e:
            logging.error(f"Failed to save report to file: {e}")
    
    def get_port_label(self, port):
        """Get the label for a specific port from configuration"""
        for section_name, section_data in self.config.items():
            if section_name.startswith('port_'):
                if section_data.get('port') == port:
                    return section_data.get('label', '')
        return ''
    
    def get_port_port_label(self, port):
        """Get the port_label for a specific port from configuration"""
        for section_name, section_data in self.config.items():
            if section_name.startswith('port_'):
                if section_data.get('port') == port:
                    return section_data.get('port_label', '')
        return ''
    
    def get_port_post_command(self, port):
        """Get the post_command for a specific port from configuration"""
        for section_name, section_data in self.config.items():
            if section_name.startswith('port_'):
                if section_data.get('port') == port:
                    return section_data.get('post_command', '')
        return ''
    
    def execute_post_command(self, command_template, host, port=None):
        """Execute post_command for a specific host"""
        if not command_template:
            return ''
        
        try:
            # Replace {host} and {port} placeholders with actual values
            command = command_template.format(host=host, port=port or '')
            
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=60,  # 1 minute timeout for post commands
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logging.warning(f"Post command failed for {host}: {result.stderr}")
                return f"[Command failed: {result.stderr.strip()}]"
                
        except subprocess.TimeoutExpired:
            logging.warning(f"Post command timed out for {host}")
            return "[Command timed out]"
        except Exception as e:
            logging.error(f"Error executing post command for {host}: {e}")
            return f"[Command error: {str(e)}]"
    
    def scan_ports(self):
        """Scan all configured ports and update database"""
        report_groups = {}
        
        for section_name, section_data in self.config.items():
            if not section_name.startswith('port_'):
                continue
            
            port = section_data.get('port')
            email = section_data.get('email')
            label = section_data.get('label')
            command = section_data.get('command')
            nmap_scan = section_data.get('nmap_scan')
            
            if not port:
                logging.warning(f"Invalid port configuration in {section_name}: missing port")
                continue
            
            # Create grouping key: label+email combination
            # If no label, use port as individual group
            # If no email, use None for report-only mode
            group_key = (label or f"Port_{port}", email)
            
            # Initialize report group if not exists
            if group_key not in report_groups:
                report_groups[group_key] = {
                    'label': label or f"Port_{port}",
                    'email': email,
                    'ports': {}
                }
            
            # Determine scanning method and handle failures
            ip_addresses = []
            scan_success = True
            scan_error = None
            
            try:
                if nmap_scan:
                    logging.info(f"Scanning port {port} using nmap: {nmap_scan}")
                    ip_addresses = self.nmap_scan(nmap_scan, port)
                elif command:
                    logging.info(f"Scanning port {port} using command: {command}")
                    ip_addresses = self.execute_command(command, port)
                else:
                    logging.warning(f"No scan method defined for port {port}")
                    scan_success = False
                    scan_error = "No scan method defined"
                    report_groups[group_key]['ports'][port] = {'error': scan_error, 'hosts': []}
                    continue
            except Exception as e:
                logging.error(f"Scan failed for port {port}: {e}")
                scan_success = False
                scan_error = str(e)
                ip_addresses = []
                # Store scan failure information immediately
                report_groups[group_key]['ports'][port] = {'hosts': [], 'error': scan_error}
                continue
            
            # Update database and collect new hosts (only if scan was successful)
            if scan_success:
                new_hosts = self.update_host_database(port, ip_addresses)
                report_groups[group_key]['ports'][port] = {'hosts': new_hosts, 'error': None}
            else:
                # Store scan failure information
                report_groups[group_key]['ports'][port] = {'hosts': [], 'error': scan_error}
        
        # Generate reports for each group (label+email combination)
        for group_key, group_data in report_groups.items():
            self.generate_report(group_data['email'], group_data['ports'], group_data['label'])
    
    def run_cron_mode(self):
        """Run once for cron mode"""
        logging.info("Running Harbinger in cron mode")
        self.scan_ports()
        logging.info("Cron mode scan completed")
    
    def run_standalone_mode(self):
        """Run continuously in standalone mode"""
        logging.info("Running Harbinger in standalone mode")
        
        # Schedule reports based on config
        report_time = self.config.get('standalone', {}).get('report_time', '08:00')
        schedule.every().day.at(report_time).do(self.scan_ports)
        
        logging.info(f"Reports scheduled for daily at {report_time}")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logging.info("Standalone mode interrupted by user")
        except Exception as e:
            logging.error(f"Error in standalone mode: {e}")
            raise


def main():
    parser = argparse.ArgumentParser(description='Harbinger - Network Host Monitoring Tool')
    parser.add_argument('--config', '-c', default='harbinger.yaml',
                       help='Configuration file path (default: harbinger.yaml)')
    parser.add_argument('--mode', choices=['cron', 'standalone'], required=True,
                       help='Run mode: cron (single run) or standalone (continuous)')
    
    args = parser.parse_args()
    
    try:
        monitor = HarbingerMonitor(args.config)
        
        if args.mode == 'cron':
            monitor.run_cron_mode()
        elif args.mode == 'standalone':
            monitor.run_standalone_mode()
            
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
