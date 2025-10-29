#!/usr/bin/env python3
"""
Minimal Apache ActiveMQ Web Console Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Apache ActiveMQ Web Console connectivity and reports security configuration:
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

def test_activemq_connection(host, port, use_ssl=False):
    """Test basic ActiveMQ Web Console connection"""
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

def test_activemq_web(host, port, use_ssl=False):
    """Test ActiveMQ Web Console and authentication requirements"""
    try:
        protocol = "https" if use_ssl else "http"
        # ActiveMQ Web Console is typically at /admin/ or just the root
        url = f"{protocol}://{host}:{port}/admin/"
        
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
            
            opener.addheaders = [('User-Agent', 'ActiveMQ-Web-Security-Scanner')]
            response = opener.open(req, timeout=5)
            response_data = response.read().decode('utf-8', errors='ignore')
            response.close()
            
            # Check if we got ActiveMQ web console (look for ActiveMQ indicators)
            if response_data and ('ActiveMQ' in response_data or 'apache' in response_data.lower() or 'activemq' in response_data.lower()):
                # Check if it's asking for authentication or if we got content
                if 'login' in response_data.lower() and 'password' in response_data.lower():
                    # Login page shown - authentication required, but we can access it
                    return False, "Authentication required", "Web Console accessible - login page shown"
                elif '401' in response_data or 'unauthorized' in response_data.lower():
                    # Got 401 response
                    return test_activemq_default_creds(host, port, use_ssl)
                else:
                    # Got content without authentication
                    return True, None, "No authentication required - Web Console accessible without credentials"
            else:
                # Try root path
                return test_activemq_root(host, port, use_ssl)
                
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Authentication required - try default credentials
                return test_activemq_default_creds(host, port, use_ssl)
            elif e.code == 403:
                return False, "Authentication required", "Access forbidden - authentication required"
            elif e.code == 404:
                # Try root path
                return test_activemq_root(host, port, use_ssl)
            else:
                return False, f"HTTP {e.code}", f"Web Console error: {str(e)}"
                
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
            return False, f"Not an ActiveMQ Web Console - {str(e)}", None

def test_activemq_root(host, port, use_ssl=False):
    """Test ActiveMQ root path"""
    try:
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/"
        
        req = urllib.request.Request(url)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
        
        opener.addheaders = [('User-Agent', 'ActiveMQ-Web-Security-Scanner')]
        response = opener.open(req, timeout=5)
        response_data = response.read().decode('utf-8', errors='ignore')
        response.close()
        
        if response_data and ('ActiveMQ' in response_data or 'apache' in response_data.lower() or 'activemq' in response_data.lower()):
            if '401' in response_data or 'unauthorized' in response_data.lower():
                return test_activemq_default_creds(host, port, use_ssl)
            else:
                return True, None, "No authentication required - Web Console accessible without credentials"
        else:
            return False, "ActiveMQ Web Console not found", "Web Console may not be enabled or different path"
            
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return test_activemq_default_creds(host, port, use_ssl)
        else:
            return False, f"HTTP {e.code}", None
    except Exception:
        return False, "ActiveMQ Web Console not found", None

def test_activemq_default_creds(host, port, use_ssl=False):
    """Test ActiveMQ Web Console with default credentials (admin/admin)"""
    try:
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/admin/"
        
        # Try with default credentials
        credentials = base64.b64encode(b"admin:admin").decode('utf-8')
        
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Basic {credentials}')
        req.add_header('User-Agent', 'ActiveMQ-Web-Security-Scanner')
        
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
        
        response = opener.open(req, timeout=5)
        response_data = response.read().decode('utf-8', errors='ignore')
        response.close()
        
        # Check if we got ActiveMQ web console content
        if response_data and ('ActiveMQ' in response_data or 'apache' in response_data.lower() or 'activemq' in response_data.lower()):
            # If we still see login page, credentials didn't work
            if 'login' in response_data.lower() and 'password' in response_data.lower():
                return False, "Authentication required", "Default credentials rejected - valid credentials required"
            else:
                return False, "Default credentials working - admin/admin accepted", "VULNERABLE: Default credentials work"
        else:
            return False, "Authentication required", "Valid credentials required"
            
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "Authentication required", "Valid credentials required (default admin/admin rejected)"
        else:
            return False, f"HTTP {e.code}", f"Web Console error: {str(e)}"
    except Exception:
        return False, "Authentication required", "Valid credentials required"

def scan_activemq_security(host, port=8161, tls_only=False):
    """Scan ActiveMQ Web Console security configuration"""
    
    if tls_only:
        # Test only TLS/SSL connection
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        
        if test_activemq_connection(host, port, use_ssl=True):
            success, error, info = test_activemq_web(host, port, use_ssl=True)
            
            if success:
                print(info)
                return
            else:
                print(error)
                if info:
                    print(info)
                return
        else:
            print("TLS connection failed")
            return
    
    # Default behavior - test only plain connection (no TLS)
    print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
    
    if test_activemq_connection(host, port, use_ssl=False):
        success, error, info = test_activemq_web(host, port, use_ssl=False)
        
        if success:
            print(info)
            return
        else:
            print(error)
            if info:
                print(info)
            return
    else:
        print("Plain connection failed")
        return

def main():
    parser = argparse.ArgumentParser(description='Apache ActiveMQ Web Console Security Scanner')
    parser.add_argument('host', help='ActiveMQ host to test')
    parser.add_argument('port', nargs='?', type=int, default=8161, help='ActiveMQ Web Console port (default: 8161)')
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
    
    scan_activemq_security(host, port, tls_only)

if __name__ == '__main__':
    main()

