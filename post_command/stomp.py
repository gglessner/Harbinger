#!/usr/bin/env python3
"""
Minimal STOMP Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests STOMP connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import time
import os
import argparse

def test_stomp_connection(host, port, use_ssl=False):
    """Test basic STOMP connection"""
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

def test_stomp_websocket(host, port, use_ssl=False):
    """Test STOMP over WebSocket"""
    try:
        # Create socket connection
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            wrapped_socket = context.wrap_socket(sock, server_hostname=host)
            wrapped_socket.connect((host, port))
            conn = wrapped_socket
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            conn = sock
        
        # Send WebSocket handshake
        protocol = "wss" if use_ssl else "ws"
        path = "/stomp"  # Common STOMP WebSocket endpoint
        ws_key = "testkey"
        
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: v11.stomp\r\n"
            f"\r\n"
        )
        
        conn.send(handshake.encode('utf-8'))
        
        # Read response
        response = conn.recv(4096).decode('utf-8', errors='ignore')
        conn.close()
        
        if '101 Switching Protocols' in response and 'upgrade: websocket' in response.lower():
            # WebSocket connection successful, would need to send STOMP over WS
            return True, None, "WebSocket detected - STOMP over WebSocket supported"
        else:
            return False, None, None
    except Exception:
        return False, None, None

def test_stomp_protocol(host, port, use_ssl=False):
    """Test STOMP protocol and authentication requirements"""
    try:
        # Create socket connection
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            wrapped_socket = context.wrap_socket(sock, server_hostname=host)
            wrapped_socket.connect((host, port))
            conn = wrapped_socket
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            conn = sock
        
        # Try to connect without credentials
        connect_frame = "CONNECT\naccept-version:1.0,1.1,1.2\nhost:{}\n\n\x00".format(host)
        conn.send(connect_frame.encode('utf-8'))
        
        # Read response
        response = conn.recv(4096).decode('utf-8')
        conn.close()
        
        if response.startswith('CONNECTED'):
            return True, None, "No authentication required"
        elif response.startswith('ERROR'):
            error_msg = response
            if 'auth' in error_msg.lower() or 'login' in error_msg.lower() or 'credential' in error_msg.lower():
                return False, "Authentication required", "STOMP server requires authentication"
            else:
                return False, f"STOMP error - {error_msg}", None
        else:
            # Check if response looks like WebSocket upgrade
            if 'upgrade:' in response.lower() or 'websocket' in response.lower():
                return False, "WebSocket required", "Server expects WebSocket connection, not TCP STOMP"
            return False, f"Unexpected response - {response[:100]}", None
            
    except socket.timeout:
        return False, "Connection timeout - service not responding", None
    except ConnectionRefusedError:
        return False, "Connection refused - service not running", None
    except ssl.SSLError as e:
        return False, f"TLS connection failed - {str(e)}", None
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            return False, "Connection refused - service not running", None
        elif 'timeout' in error_msg:
            return False, "Connection timeout - service not responding", None
        elif 'ssl' in error_msg or 'certificate' in error_msg or 'tls' in error_msg:
            return False, f"TLS connection failed - {str(e)}", None
        else:
            return False, f"Not a STOMP service - {str(e)}", None

def scan_stomp_security(host, port=61613, tls_only=False):
    """Scan STOMP security configuration"""
    
    if tls_only:
        # Test only TLS/SSL connection
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        
        if test_stomp_connection(host, port, use_ssl=True):
            success, error, info = test_stomp_protocol(host, port, use_ssl=True)
            
            if success:
                print(info)
                if info and "No authentication required" in info:
                    print("VULNERABLE")
                return
            elif error == "WebSocket required":
                # Try WebSocket STOMP with TLS instead
                print("TCP STOMP over TLS failed - trying WebSocket STOMP over WSS...", file=sys.stderr)
                ws_success, ws_error, ws_info = test_stomp_websocket(host, port, use_ssl=True)
                if ws_success and ws_info:
                    print(ws_info)
                    return
                else:
                    print(error)
                    return
            else:
                print(error)
                return
        else:
            print("TLS connection failed")
            return
    
    # Default behavior - test only plain connection (no TLS)
    print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
    
    if test_stomp_connection(host, port, use_ssl=False):
        success, error, info = test_stomp_protocol(host, port, use_ssl=False)
        
        if success:
            print(info)
            if info and "No authentication required" in info:
                print("VULNERABLE")
            return
        elif error == "WebSocket required":
            # Try WebSocket STOMP instead
            print("TCP STOMP failed - trying WebSocket STOMP...", file=sys.stderr)
            ws_success, ws_error, ws_info = test_stomp_websocket(host, port, use_ssl=False)
            if ws_success and ws_info:
                print(ws_info)
                return
            else:
                print(error)
                return
        else:
            print(error)
            return
    else:
        print("Plain connection failed")
        return

def main():
    parser = argparse.ArgumentParser(description='STOMP Security Scanner')
    parser.add_argument('host', help='STOMP host to test')
    parser.add_argument('port', nargs='?', type=int, default=61613, help='STOMP port (default: 61613)')
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
    
    scan_stomp_security(host, port, tls_only)

if __name__ == '__main__':
    main()

