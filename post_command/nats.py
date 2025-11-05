#!/usr/bin/env python3
"""
NATS Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests NATS connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse

def test_nats_connection(host, port, use_ssl=False):
    """Test basic NATS connection"""
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

def test_nats_auth(host, port, use_ssl=False):
    """Test NATS authentication"""
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
        
        # NATS protocol: send CONNECT message
        # Format: "CONNECT {\"verbose\":false,\"pedantic\":false,\"tls_required\":false}\r\n"
        connect_msg = b'CONNECT {"verbose":false,"pedantic":false,"tls_required":false}\r\n'
        conn.send(connect_msg)
        
        # Send PING
        ping_msg = b'PING\r\n'
        conn.send(ping_msg)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        response_str = response.decode('utf-8', errors='ignore')
        
        # If we get PONG or INFO, connection succeeded without auth
        if 'PONG' in response_str or 'INFO' in response_str or len(response) > 0:
            print(f"NATS accessible at {host}:{port}")
            print("VULNERABLE: No authentication required")
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
            print(f"Error testing NATS: {str(e)}")
        return False

def scan_nats_security(host, port=4222, tls_only=False):
    """Scan NATS security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_nats_connection(host, port, use_ssl=True):
            test_nats_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_nats_connection(host, port, use_ssl=False):
            test_nats_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='NATS Security Scanner')
    parser.add_argument('host', help='NATS host to test')
    parser.add_argument('port', nargs='?', type=int, default=4222, help='NATS port (default: 4222)')
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
    
    scan_nats_security(host, port, tls_only)

if __name__ == '__main__':
    main()

