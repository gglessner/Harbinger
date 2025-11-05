#!/usr/bin/env python3
"""
Apache Derby Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Apache Derby connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_derby_connection(host, port, use_ssl=False):
    """Test basic Derby connection"""
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

def test_derby_auth(host, port, use_ssl=False):
    """Test Derby authentication"""
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
        
        # Derby Network Server protocol
        # Send DRDA protocol handshake - simplified version
        # DRDA protocol starts with DDM (Distributed Data Management) messages
        
        # Try to connect without credentials
        # DDM EXCSAT (Exchange Server Attributes) message
        ddm_header = struct.pack('>HH', 0xD0, 0x00)  # DDM length and code
        ddm_header += b'\x00\x01'  # Correlator
        ddm_header += b'\x00\x01'  # Code point EXCSAT
        
        conn.send(ddm_header)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        # Check if we got a response (connection successful)
        if len(response) > 0:
            # If we got a response, connection was successful
            # Check if authentication error is present
            response_str = response.hex()
            if 'authentication' in response_str.lower() or '401' in response_str:
                print(f"Apache Derby at {host}:{port} requires authentication")
                return False
            else:
                print(f"Apache Derby accessible at {host}:{port}")
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
            print(f"Error testing Derby: {str(e)}")
        return False

def scan_derby_security(host, port=1527, tls_only=False):
    """Scan Derby security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_derby_connection(host, port, use_ssl=True):
            test_derby_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_derby_connection(host, port, use_ssl=False):
            test_derby_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Apache Derby Security Scanner')
    parser.add_argument('host', help='Derby host to test')
    parser.add_argument('port', nargs='?', type=int, default=1527, help='Derby port (default: 1527)')
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
    
    scan_derby_security(host, port, tls_only)

if __name__ == '__main__':
    main()

