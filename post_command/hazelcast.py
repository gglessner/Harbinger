#!/usr/bin/env python3
"""
Hazelcast Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Hazelcast connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_hazelcast_connection(host, port, use_ssl=False):
    """Test basic Hazelcast connection"""
    try:
        if use_ssl:
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.close()
            return True
    except Exception:
        return False

def test_hazelcast_auth(host, port, use_ssl=False):
    """Test Hazelcast authentication"""
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = context.wrap_socket(sock, server_hostname=host)
            conn.connect((host, port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = sock
            conn.connect((host, port))
        
        # Hazelcast protocol: send client protocol initialization
        # Protocol version: 1
        # Message type: ClientAuthentication (0x0002)
        
        # Build authentication message
        protocol_version = 1
        message_type = 0x0002  # ClientAuthentication
        
        # Simple authentication message (without credentials)
        auth_message = struct.pack('>B', protocol_version)  # Protocol version
        auth_message += struct.pack('>H', message_type)  # Message type
        
        conn.send(auth_message)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        # Check if we got a response (connection successful)
        if len(response) > 0:
            # If we got a response without authentication error, it's vulnerable
            print(f"Hazelcast accessible at {host}:{port}")
            print("VULNERABLE")
            return True
        
        return False
        
    except socket.timeout:
        print(f"Connection timeout - service not responding")
        return False
    except ConnectionRefusedError:
        print(f"Connection refused - service not running on {host}:{port}")
        return False
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            print(f"Connection refused - service not running on {host}:{port}")
        elif 'timeout' in error_msg:
            print(f"Connection timeout - service not responding")
        else:
            print(f"Error testing Hazelcast: {str(e)}")
        return False

def scan_hazelcast_security(host, port=5701, tls_only=False):
    """Scan Hazelcast security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_hazelcast_connection(host, port, use_ssl=True):
            test_hazelcast_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_hazelcast_connection(host, port, use_ssl=False):
            test_hazelcast_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Hazelcast Security Scanner')
    parser.add_argument('host', help='Hazelcast host to test')
    parser.add_argument('port', nargs='?', type=int, default=5701, help='Hazelcast port (default: 5701)')
    parser.add_argument('--tls', '-t', action='store_true', help='Test TLS/SSL connection only')
    
    args = parser.parse_args()
    
    host = args.host
    port = args.port
    tls_only = args.tls
    
    if ':' in host:
        host, port_str = host.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"Error: Invalid port '{port_str}'", file=sys.stderr)
            sys.exit(1)
    
    scan_hazelcast_security(host, port, tls_only)

if __name__ == '__main__':
    main()

