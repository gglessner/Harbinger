#!/usr/bin/env python3
"""
Mosquitto MQTT Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Mosquitto MQTT connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_mosquitto_connection(host, port, use_ssl=False):
    """Test basic Mosquitto MQTT connection"""
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

def test_mosquitto_auth(host, port, use_ssl=False):
    """Test Mosquitto MQTT authentication"""
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
        
        # MQTT CONNECT packet: try to connect without username/password
        # Fixed header: 0x10 (CONNECT), remaining length
        # Variable header: protocol name "MQTT", protocol level 4, flags, keep alive
        # Payload: client ID
        
        client_id = b"Harbinger-Scanner"
        protocol_name = b"MQTT"
        protocol_level = 4
        connect_flags = 0x02  # Clean session, no username, no password
        
        # Build CONNECT packet
        variable_header = struct.pack('!H', len(protocol_name)) + protocol_name
        variable_header += struct.pack('!B', protocol_level)
        variable_header += struct.pack('!B', connect_flags)
        variable_header += struct.pack('!H', 60)  # Keep alive
        
        payload = struct.pack('!H', len(client_id)) + client_id
        
        remaining_length = len(variable_header) + len(payload)
        fixed_header = struct.pack('!B', 0x10)  # CONNECT
        # Encode remaining length (simplified for small values)
        if remaining_length < 128:
            fixed_header += struct.pack('!B', remaining_length)
        else:
            # Multi-byte encoding would be needed for larger values
            fixed_header += struct.pack('!B', 0x80 | (remaining_length & 0x7F))
            fixed_header += struct.pack('!B', remaining_length >> 7)
        
        connect_packet = fixed_header + variable_header + payload
        conn.send(connect_packet)
        
        # Read CONNACK response
        response = conn.recv(4096)
        conn.close()
        
        # Check response - CONNACK is 0x20, if we get it, connection succeeded
        if len(response) >= 2:
            if response[0] == 0x20:  # CONNACK
                return_code = response[1] if len(response) > 1 else 0
                if return_code == 0:  # Connection accepted
                    print(f"Mosquitto MQTT accessible at {host}:{port}")
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
            print(f"Error testing Mosquitto MQTT: {str(e)}")
        return False

def scan_mosquitto_security(host, port=1883, tls_only=False):
    """Scan Mosquitto MQTT security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_mosquitto_connection(host, port, use_ssl=True):
            test_mosquitto_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_mosquitto_connection(host, port, use_ssl=False):
            test_mosquitto_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Mosquitto MQTT Security Scanner')
    parser.add_argument('host', help='Mosquitto MQTT host to test')
    parser.add_argument('port', nargs='?', type=int, default=1883, help='Mosquitto MQTT port (default: 1883)')
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
    
    scan_mosquitto_security(host, port, tls_only)

if __name__ == '__main__':
    main()

