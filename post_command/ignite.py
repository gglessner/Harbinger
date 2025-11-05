#!/usr/bin/env python3
"""
Apache Ignite Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Apache Ignite connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_ignite_connection(host, port, use_ssl=False):
    """Test basic Ignite connection"""
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

def test_ignite_auth(host, port, use_ssl=False):
    """Test Ignite authentication"""
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
        
        # Apache Ignite uses a custom binary protocol
        # Try to send a handshake/version request
        # Ignite protocol: magic (2 bytes) + version (2 bytes) + commands
        
        # Handshake message
        magic = 0x0001  # Ignite protocol magic
        version = 0x0100  # Protocol version 1.0
        
        handshake = struct.pack('>HH', magic, version)
        
        conn.send(handshake)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        # Check if we got a response (connection successful)
        if len(response) >= 2:
            # Parse response magic
            resp_magic = struct.unpack('>H', response[0:2])[0]
            if resp_magic == 0x0001:  # Valid Ignite response
                print(f"Apache Ignite accessible at {host}:{port}")
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
            print(f"Error testing Ignite: {str(e)}")
        return False

def scan_ignite_security(host, port=47500, tls_only=False):
    """Scan Ignite security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_ignite_connection(host, port, use_ssl=True):
            test_ignite_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_ignite_connection(host, port, use_ssl=False):
            test_ignite_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Apache Ignite Security Scanner')
    parser.add_argument('host', help='Ignite host to test')
    parser.add_argument('port', nargs='?', type=int, default=47500, help='Ignite port (default: 47500)')
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
    
    scan_ignite_security(host, port, tls_only)

if __name__ == '__main__':
    main()

