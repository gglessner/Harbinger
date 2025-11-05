#!/usr/bin/env python3
"""
LDAP Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests LDAP connectivity and reports security configuration:
- Anonymous bind enabled (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_ldap_connection(host, port, use_ssl=False):
    """Test basic LDAP connection"""
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

def test_ldap_auth(host, port, use_ssl=False):
    """Test LDAP anonymous bind"""
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
        
        # LDAP Bind Request (anonymous)
        # LDAP protocol: ASN.1 BER encoding
        # Simplified bind request packet
        
        # LDAP Message: [APPLICATION 0] SEQUENCE {
        #   messageID INTEGER,
        #   protocolOp CHOICE {
        #     bindRequest BindRequest
        #   }
        # }
        
        # Bind Request: [APPLICATION 0] SEQUENCE {
        #   version INTEGER,
        #   name LDAPDN,
        #   authentication CHOICE {
        #     simple AuthenticationChoice
        #   }
        # }
        
        # Simplified anonymous bind
        # 0x30 = SEQUENCE
        # Message ID: 0x02 0x01 0x01 (1)
        # Bind Request: 0x60 (APPLICATION 0)
        # Version: 0x02 0x01 0x03 (3)
        # Name: 0x04 0x00 (empty string for anonymous)
        # Authentication: 0x80 0x00 (simple auth, empty password)
        
        # Basic LDAP bind packet structure
        bind_packet = b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00'
        
        conn.send(bind_packet)
        
        # Read bind response
        response = conn.recv(4096)
        conn.close()
        
        # LDAP Bind Response: [APPLICATION 1] SEQUENCE {
        #   resultCode ENUMERATED,
        #   matchedDN LDAPDN,
        #   errorMessage LDAPString,
        #   ...
        # }
        
        # Check if bind was successful (resultCode = 0 = success)
        if len(response) > 0:
            # Parse response - look for success indicator
            # 0x30 = SEQUENCE
            # 0x61 = Bind Response (APPLICATION 1)
            # 0x0a = ENUMERATED (resultCode)
            # 0x00 = success
            
            response_hex = response.hex()
            # Look for success pattern in response
            if len(response) >= 5:
                # Check if result code indicates success
                # Success is typically indicated by 0x00 after the resultCode tag
                try:
                    # Simple check: if we get a response, try to see if it's a success
                    # LDAP success is resultCode 0
                    if b'\x0a\x01\x00' in response or b'\x00' in response[3:6]:
                        print(f"LDAP accessible at {host}:{port}")
                        print("VULNERABLE: Anonymous bind enabled")
                        print("VULNERABLE")
                        return True
                except:
                    pass
        
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
            print(f"Error testing LDAP: {str(e)}")
        return False

def scan_ldap_security(host, port=389, tls_only=False):
    """Scan LDAP security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_ldap_connection(host, port, use_ssl=True):
            test_ldap_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_ldap_connection(host, port, use_ssl=False):
            test_ldap_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='LDAP Security Scanner')
    parser.add_argument('host', help='LDAP host to test')
    parser.add_argument('port', nargs='?', type=int, default=389, help='LDAP port (default: 389)')
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
    
    scan_ldap_security(host, port, tls_only)

if __name__ == '__main__':
    main()

