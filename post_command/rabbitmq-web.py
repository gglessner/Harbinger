#!/usr/bin/env python3
"""
Minimal RabbitMQ Management Web API Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests RabbitMQ Management Web HTTP API connectivity and reports security configuration:
- No authentication required (vulnerable)
- Default credentials working (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import time
import os
import argparse
import urllib.request
import urllib.error
import base64

def test_rabbitmq_connection(host, port, use_ssl=False):
    """Test basic RabbitMQ Management API connection"""
    try:
        if use_ssl:
            # Test with SSL/TLS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            wrapped_socket = context.wrap_socket(sock, server_hostname=host)
            wrapped_socket.connect((host, port))
            wrapped_socket.close()
            return True
        else:
            # Test without SSL/TLS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.close()
            return True
    except Exception:
        return False

def test_rabbitmq_api(host, port, use_ssl=False):
    """Test RabbitMQ Management API and authentication requirements"""
    try:
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/api/overview"
        
        # Try without authentication first
        try:
            req = urllib.request.Request(url)
            if use_ssl:
                # Disable SSL verification
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
            else:
                opener = urllib.request.build_opener()
            
            opener.addheaders = [('User-Agent', 'RabbitMQ-Security-Scanner')]
            response = opener.open(req, timeout=5)
            response_data = response.read().decode('utf-8')
            response.close()
            
            # If we got data, check if it's valid JSON (RabbitMQ API returns JSON)
            if response_data and ('management_version' in response_data or 'rabbitmq_version' in response_data or 'node' in response_data):
                return True, None, "No authentication required - Management API accessible without credentials"
            else:
                return False, "Unexpected response", None
                
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Authentication required - try default credentials
                return test_rabbitmq_default_creds(host, port, use_ssl)
            elif e.code == 403:
                return False, "Authentication required", "Access forbidden - authentication required"
            elif e.code == 404:
                return False, "Management API not found", "Management plugin may not be enabled"
            else:
                return False, f"HTTP {e.code}", f"Management API error: {str(e)}"
                
        except urllib.error.URLError as e:
            error_msg = str(e).lower()
            if 'connection refused' in error_msg or 'connection reset' in error_msg:
                return False, "Connection refused", "Service not running or port not open"
            elif 'timeout' in error_msg:
                return False, "Connection timeout", "Service not responding"
            elif 'ssl' in error_msg or 'certificate' in error_msg:
                return False, f"TLS connection failed - {str(e)}", None
            else:
                return False, f"Connection error - {str(e)}", None
                
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            return False, "Connection refused - service not running", None
        elif 'timeout' in error_msg:
            return False, "Connection timeout - service not responding", None
        elif 'ssl' in error_msg or 'certificate' in error_msg or 'tls' in error_msg:
            return False, f"TLS connection failed - {str(e)}", None
        else:
            return False, f"Not a RabbitMQ Management API - {str(e)}", None

def test_rabbitmq_default_creds(host, port, use_ssl=False):
    """Test RabbitMQ Management API with default credentials (guest/guest)"""
    try:
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/api/overview"
        
        # Try with default credentials
        credentials = base64.b64encode(b"guest:guest").decode('utf-8')
        
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Basic {credentials}')
        req.add_header('User-Agent', 'RabbitMQ-Security-Scanner')
        
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
        
        response = opener.open(req, timeout=5)
        response_data = response.read().decode('utf-8')
        response.close()
        
        # Check if we got valid RabbitMQ API response
        if response_data and ('management_version' in response_data or 'rabbitmq_version' in response_data or 'node' in response_data):
            return False, "Default credentials working - guest/guest accepted", "VULNERABLE: Default credentials work"
        else:
            return False, "Authentication required", "Valid credentials required"
            
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "Authentication required", "Valid credentials required (default guest/guest rejected)"
        else:
            return False, f"HTTP {e.code}", f"Management API error: {str(e)}"
    except Exception:
        return False, "Authentication required", "Valid credentials required"

def scan_rabbitmq_security(host, port=15672, tls_only=False):
    """Scan RabbitMQ Management API security configuration"""
    
    if tls_only:
        # Test only TLS/SSL connection
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        
        if test_rabbitmq_connection(host, port, use_ssl=True):
            success, error, info = test_rabbitmq_api(host, port, use_ssl=True)
            
            if success:
                print(info)
                print("VULNERABLE")
                return
            else:
                print(error)
                if info:
                    print(info)
                    if "VULNERABLE" in info:
                        print("VULNERABLE")
                return
        else:
            print("TLS connection failed")
            return
    
    # Default behavior - test only plain connection (no TLS)
    print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
    
    if test_rabbitmq_connection(host, port, use_ssl=False):
        success, error, info = test_rabbitmq_api(host, port, use_ssl=False)
        
        if success:
            print(info)
            print("VULNERABLE")
            return
        else:
            print(error)
            if info:
                print(info)
                if "VULNERABLE" in info:
                    print("VULNERABLE")
            return
    else:
        print("Plain connection failed")
        return

def main():
    parser = argparse.ArgumentParser(description='RabbitMQ Management API Security Scanner')
    parser.add_argument('host', help='RabbitMQ host to test')
    parser.add_argument('port', nargs='?', type=int, default=15672, help='RabbitMQ Management API port (default: 15672)')
    parser.add_argument('--tls', '-t', action='store_true', help='Test TLS/SSL connection only')
    
    args = parser.parse_args()
    
    host = args.host
    port = args.port
    tls_only = args.tls
    
    # Check if port is specified in host (host:port format)
    if ':' in host:
        host, port_str = host.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"Error: Invalid port '{port_str}'", file=sys.stderr)
            sys.exit(1)
    
    scan_rabbitmq_security(host, port, tls_only)

if __name__ == '__main__':
    main()

